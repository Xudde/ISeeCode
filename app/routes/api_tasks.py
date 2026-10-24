"""任务管理 API：上传（含去重）+ 列表 + 详情 + 漏洞 + 停止 + 删除 + 报告下载 + 手工 POC"""
import hashlib
import shutil
import threading
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.audit_labels import vuln_label
from app.config import ALLOWED_EXTENSIONS, DECOMPILE_EXTENSIONS, MAX_UPLOAD_SIZE, UPLOAD_DIR
from app.models import Task, Vulnerability
from app.queue_worker import enqueue
from app.routes.api_config import get_db
from app.schemas import TaskOut, VulnerabilityOut
from app.skills import poc, sandbox

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

# 上传写库互斥锁：防止同一文件并发上传时双双通过去重检查
_upload_lock = threading.Lock()

# 活跃（可停止）状态
ACTIVE_STATUSES = ("pending", "preprocessing", "sast", "llm_judging", "agent_analyzing",
                   "agent_full_audit", "sandbox_deploying", "poc_verifying", "reporting")
# 去重时视为"已在审计/已审计"的状态
DEDUP_BLOCK_STATUSES = ACTIVE_STATUSES + ("completed",)


@router.post("/upload", response_model=TaskOut)
async def upload_zip(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """上传源码包，创建任务并入队；同内容文件自动去重，避免重复审计浪费 token"""
    ext = Path(file.filename).suffix.lower()
    is_dockerfile = "dockerfile" in file.filename.lower() or ext == ".dockerfile"
    if ext == ".apk":
        ptype = "apk"
    elif is_dockerfile or ext == ".tar":
        ptype = "image"
    elif ext in DECOMPILE_EXTENSIONS:
        ptype = "decompile"
    elif ext in ALLOWED_EXTENSIONS:
        ptype = "web"
    else:
        raise HTTPException(status_code=400, detail="支持 .zip 源码包 / .apk 应用 / .tar 镜像包 / Dockerfile / 反编译文件（.jar .war .class .dex .dll .exe .pyc .so .elf）")

    # 流式接收：避免大文件一次性读入内存导致超时/断连，需重传
    chunks = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)  # 1MB 分块
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail="文件超过 200MB 上限")
        chunks.append(chunk)
    content = b"".join(chunks)
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="文件为空")

    file_hash = hashlib.sha256(content).hexdigest()

    with _upload_lock:
        # 同内容文件去重：已有任务正在审计或已完成，直接指向旧任务，不重复消耗 token
        dup = db.query(Task).filter(Task.file_hash == file_hash).order_by(Task.id.asc()).first()
        if dup and dup.status in DEDUP_BLOCK_STATUSES:
            raise HTTPException(
                status_code=409,
                detail=f"相同文件已存在（任务 #{dup.id}，状态：{dup.status}），已避免重复审计浪费 token。请直接查看该任务结果。",
            )

        # 保存
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_name = f"{ts}_{Path(file.filename).name}"
        save_path = UPLOAD_DIR / safe_name
        save_path.write_bytes(content)

        task = Task(filename=file.filename, file_hash=file_hash,
                    upload_path=str(save_path), workspace_path=str(save_path), project_type=ptype)
        db.add(task)
        db.commit()
        db.refresh(task)

    enqueue(task.id)
    return task


@router.get("", response_model=list[TaskOut])
def list_tasks(db: Session = Depends(get_db)):
    return db.query(Task).order_by(Task.id.desc()).all()


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: int, db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task


@router.get("/{task_id}/vulns", response_model=list[VulnerabilityOut])
def get_task_vulns(task_id: int, db: Session = Depends(get_db)):
    return db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()


@router.post("/{task_id}/stop")
def stop_task(task_id: int, db: Session = Depends(get_db)):
    """请求停止任务：协作式取消，worker 在阶段间检查并清理沙箱"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status not in ACTIVE_STATUSES:
        raise HTTPException(status_code=400, detail=f"任务已结束（{task.status}），无需停止")
    task.cancel_requested = True
    if task.status == "pending":
        task.status = "cancelled"  # 还在队列里，直接标记取消
    db.commit()
    return {"ok": True, "id": task.id, "status": task.status}


@router.delete("/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    """删除任务：清理数据库记录与上传/工作区/报告文件；运行中的任务需先停止"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.status in ACTIVE_STATUSES and not task.cancel_requested:
        raise HTTPException(status_code=409, detail="任务正在运行，请先停止后再删除")

    db.query(Vulnerability).filter(Vulnerability.task_id == task_id).delete()
    # 销毁保留的沙箱容器（手工 POC 验证用），避免容器残留
    if getattr(task, "sandbox_cid", None):
        try:
            import docker
            docker.from_env().containers.get(task.sandbox_cid).remove(force=True)
        except Exception:
            pass
    paths = {task.upload_path, task.workspace_path}
    if task.report_path:
        paths.add(task.report_path)
        paths.add(str(Path(task.report_path).with_suffix(".md")))
    db.delete(task)
    db.commit()

    for p in paths:
        if not p:
            continue
        try:
            fp = Path(p)
            if fp.is_dir():
                shutil.rmtree(fp, ignore_errors=True)
            elif fp.exists():
                fp.unlink(missing_ok=True)
        except Exception:
            pass
    return {"ok": True, "id": task_id}


@router.get("/{task_id}/report")
def download_report(task_id: int, db: Session = Depends(get_db), format: str = "html"):
    """下载报告：默认自包含 HTML，format=md 下载 Markdown 版本"""
    task = db.get(Task, task_id)
    if task is None or not task.report_path or not Path(task.report_path).exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    if format == "md":
        md_path = Path(task.report_path).with_suffix(".md")
        if not md_path.exists():
            raise HTTPException(status_code=404, detail="Markdown 报告不存在")
        return FileResponse(md_path, media_type="text/markdown", filename=f"task_{task_id}_report.md")
    return FileResponse(
        task.report_path,
        media_type="text/html",
        filename=f"task_{task_id}_report.html",
    )


@router.post("/{task_id}/poc-test")
def poc_test(task_id: int, vuln_id: int = Body(...), payload: str = Body(""),
             db: Session = Depends(get_db)):
    """手工 POC 验证：在保留的沙箱容器内执行 payload，返回 HTTP 状态码与回显内容"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if not getattr(task, "sandbox_cid", None):
        raise HTTPException(status_code=400, detail="沙箱已销毁：仅已完成且保留沙箱的任务可手动验证")
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.task_id != task_id:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    payload = (payload or vuln.poc_payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="该漏洞没有可执行的 payload")
    req = poc.parse_poc_request(payload)
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(task.sandbox_cid)
        handle = sandbox.SandboxHandle(client, container, None, task.sandbox_port)
        url = req["route"]
        if req["query_params"]:
            qs = "&".join(f"{k}={v}" for k, v in req["query_params"].items())
            url += ("&" if "?" in url else "?") + qs
        status, text = handle.request(url, params=req["body_params"] or None, method=req["method"])
    except docker.errors.NotFound:
        raise HTTPException(status_code=400, detail="沙箱容器已不存在（可能被清理），请重新审计")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"沙箱执行失败: {e}")
    return {"status": status, "response": text[:4000]}


@router.get("/{task_id}/poc-script/{vuln_id}")
def poc_script(task_id: int, vuln_id: int, db: Session = Depends(get_db)):
    """下载该漏洞的独立 Python POC 脚本（可对真实部署执行）"""
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    vuln = db.get(Vulnerability, vuln_id)
    if vuln is None or vuln.task_id != task_id:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    payload = (vuln.poc_payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="该漏洞没有已验证 payload，无法生成 POC 脚本")
    script = poc.generate_python_poc(payload, vuln_label(vuln.rule_id))
    return Response(
        content=script,
        media_type="text/x-python",
        headers={"Content-Disposition": f'attachment; filename="poc_task{task_id}_vuln{vuln_id}.py"'},
    )
