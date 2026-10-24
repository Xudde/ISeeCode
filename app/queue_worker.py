"""串行任务队列消费器：完整流水线
preprocess → tech_detect → sast → llm_judge → sandbox → poc → agent → report
支持协作式取消（用户停止）：阶段间检查 cancel_requested，取消时清理沙箱。
任何异常不得导致线程退出。
"""
import logging
import queue
import threading
from datetime import datetime
from pathlib import Path

from app.db import SessionLocal
from app.models import Task, Vulnerability
from app.skills import apk_analyze, decompile, image_baseline, llm_judge, poc, preprocess, report, sast_semgrep, sandbox, tech_detect
from app.config import AGENT_CONCURRENCY, AGENT_MAX_STEPS
from app.agent import orchestrator

task_queue: "queue.Queue[int]" = queue.Queue()


def _log(db, task, msg: str) -> None:
    task.log = (task.log or "") + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
    db.commit()


def _maybe_cancel(db, task, handle=None) -> bool:
    """协作式取消检查：已请求停止则标记 cancelled（必要时销毁沙箱）并返回 True"""
    if task.cancel_requested or task.status == "cancelled":
        if handle is not None:
            try:
                handle.cleanup()
            except Exception:
                pass
            _log(db, task, "沙箱容器已销毁")
        task.status = "cancelled"
        task.error_msg = "任务已被用户停止"
        _log(db, task, "收到停止请求，任务已取消")
        db.commit()
        return True
    return False


def _process(task_id: int) -> None:
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        if task.status == "cancelled" or task.cancel_requested:
            task.status = "cancelled"
            task.error_msg = "任务已被用户停止"
            db.commit()
            return
        handle = None  # 沙箱句柄，取消时需清理

        # 1. 预处理：APK/镜像/反编译直接分析；zip 解压 + 初筛
        if task.project_type in ("apk", "image", "decompile"):
            task.status = "preprocessing"
            _log(db, task, f"{task.project_type} 文件就绪，跳过解压")
            vuln_dict_map = {}
        else:
            task.status = "preprocessing"
            _log(db, task, "开始预处理：解压源码包…")
            try:
                result = preprocess.run_preprocess(task, task.workspace_path)
                task.workspace_path = result["workspace"]
                suspicious = preprocess.pre_screen(result["workspace"])
                if suspicious:
                    _log(db, task, f"恶意样本初筛发现可疑文件：{', '.join(suspicious[:10])}")
                _log(db, task, f"解压完成，共 {result['total_size']} 字节")
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"预处理失败: {e}"
                _log(db, task, f"预处理失败: {e}")
                return
        if _maybe_cancel(db, task):
            return

        # 2~3. 技术栈识别 + 静态扫描
        if task.project_type == "apk":
            task.tech_stack = "android"
            task.status = "sast"
            _log(db, task, "执行 APK 静态分析（Manifest + DEX）…")
            try:
                apk_info, vulns = apk_analyze.run_apk_analysis(task.workspace_path)
                _log(db, task, f"APK 信息：{apk_info.get('package')} v{apk_info.get('version_name')}")
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"APK 分析失败: {e}"
                _log(db, task, f"APK 分析失败: {e}")
                return
        elif task.project_type == "image":
            task.tech_stack = "image"
            task.status = "sast"
            name = Path(task.filename).name
            if "dockerfile" in name.lower():
                _log(db, task, "执行 Dockerfile 基线检查…")
                try:
                    text = Path(task.workspace_path).read_text(errors="ignore")
                    vulns = image_baseline.scan_dockerfile(text)
                except Exception as e:
                    task.status = "failed"
                    task.error_msg = f"Dockerfile 解析失败: {e}"
                    _log(db, task, f"Dockerfile 解析失败: {e}")
                    return
            else:
                try:
                    img_info, vulns = image_baseline.scan_image_tar(
                        task.workspace_path, lambda m: _log(db, task, m))
                    _log(db, task, f"镜像信息：{img_info.get('image_tags')} ({img_info.get('image_id')})")
                except Exception as e:
                    task.status = "failed"
                    task.error_msg = f"镜像基线检查失败: {e}"
                    _log(db, task, f"镜像基线检查失败: {e}")
                    return
        elif task.project_type == "decompile":
            # 升级阶段 2：反编译流水线（workspace_path 保持为上传文件路径）
            task.status = "preprocessing"
            _log(db, task, "执行反编译…")
            from app.config import WORKSPACE_DIR
            dec_ws = WORKSPACE_DIR / f"task_{task.id}"
            dec_ws.mkdir(parents=True, exist_ok=True)
            try:
                dec = decompile.decompile(task.workspace_path, str(dec_ws),
                                          lambda m: _log(db, task, m))
            except Exception as e:
                dec = {"ok": False, "degraded": True, "lang": "unknown", "info": str(e)}
                _log(db, task, f"反编译异常: {e}")
            task.tech_stack = dec.get("lang", "unknown")
            vulns = []
            if dec.get("ok"):
                src = dec_ws / "decompiled"
                stacks = tech_detect.run_tech_detect_multi(str(src)) or [dec.get("lang", "unknown")]
                task.tech_stack = ",".join(stacks)
                _log(db, task, f"反编译成功（{dec['info']}），技术栈 {task.tech_stack}，产物标注“行号仅供参考”")
                task.status = "sast"
                _log(db, task, "对反编译产物执行 semgrep 扫描…")
                try:
                    vulns = sast_semgrep.run_sast(str(src), stacks)
                except Exception as e:
                    _log(db, task, f"反编译产物扫描失败: {e}")
            else:
                # 降级：字符串特征扫描
                _log(db, task, f"反编译失败（{dec.get('info','')}），降级为字符串特征扫描")
                try:
                    vulns = decompile.degrade_string_scan(task.workspace_path)
                except Exception as e:
                    _log(db, task, f"降级扫描失败: {e}")
        elif task.project_type == "web":
            techs = tech_detect.run_tech_detect_multi(task.workspace_path)
            tech = techs[0] if techs else "unknown"
            task.tech_stack = ",".join(techs) if techs else "unknown"
            _log(db, task, f"识别技术栈：{task.tech_stack}")
            if not techs:
                task.status = "skipped"
                task.error_msg = "未能识别代码语言栈（压缩包内可能不含源码文件），已跳过扫描"
                _log(db, task, "未能识别代码语言栈（压缩包内可能不含源码文件），任务标记为 skipped")
                return
            task.status = "sast"
            _log(db, task, "执行 semgrep 静态扫描…")
            try:
                vulns = sast_semgrep.run_sast(task.workspace_path, techs)
            except Exception as e:
                task.status = "failed"
                task.error_msg = f"静态扫描失败: {e}"
                _log(db, task, f"静态扫描失败: {e}")
                return
        if _maybe_cancel(db, task):
            return
        _log(db, task, f"静态扫描完成，发现 {len(vulns)} 条疑似漏洞")

        # 落库
        vuln_rows = []
        for v in vulns:
            row = Vulnerability(
                task_id=task.id,
                source={"apk": "apk", "image": "image"}.get(task.project_type, "semgrep"),
                rule_id=v["rule_id"],
                severity=v["severity"], file_path=v["file_path"],
                line=v["line"], code_snippet=v["code_snippet"],
            )
            db.add(row)
            vuln_rows.append((row, v))
        db.commit()

        # 4. 读取 LLM 配置（供 Agent 深度研判使用）。
        task.status = "llm_judging"
        llm_cfg = llm_judge.get_llm_config(db)
        if llm_cfg is None:
            _log(db, task, "未配置 LLM，跳过 Agent 深度研判")
        else:
            _log(db, task, "LLM 已配置，使用 Agent 深度研判（取代逐条片段研判）")
        if _maybe_cancel(db, task):
            return

        # 5. Docker 沙箱部署（APK/镜像/反编译任务跳过；失败不阻断，仅跳过 POC）
        if task.project_type in ("apk", "image"):
            handle = None
            if task.project_type == "apk":
                _log(db, task, "APK 任务不支持自动沙箱部署，跳过 POC 验证")
            else:
                _log(db, task, "镜像基线任务无需 POC 验证")
        elif task.project_type == "decompile":
            handle = None
            _log(db, task, "反编译任务为静态分析，跳过 POC 验证")
        else:
            task.status = "sandbox_deploying"
            _log(db, task, "部署 Docker 沙箱环境…")
            handle = sandbox.deploy_sandbox(task.workspace_path, task.tech_stack, lambda m: _log(db, task, m))
            if _maybe_cancel(db, task, handle):
                return
        # 6. POC 验证
        task.status = "poc_verifying"
        if handle is None:
            if task.project_type not in ("apk", "image", "decompile"):
                _log(db, task, "沙箱部署失败/不支持，跳过 POC 验证")
        else:
            try:
                passed = poc.verify_all(vuln_rows, task.workspace_path, handle)
                db.commit()
                _log(db, task, f"POC 验证完成：{passed}/{min(len(vuln_rows), 8)} 条验证通过")
            except Exception as e:
                _log(db, task, f"POC 验证异常: {e}")
            # 注意：容器保留到 Agent 深度研判结束再销毁（Agent 动态验证需要）
        if _maybe_cancel(db, task, handle):
            return

        # 6.5 Agent 深度研判（升级阶段 3）：配置了 LLM 才执行；优先 ERROR/WARNING，最多 AGENT_MAX_VULNS 条
        if llm_cfg is None:
            _log(db, task, "未配置 LLM，跳过 Agent 深度研判")
        else:
            from app.config import AGENT_MAX_VULNS
            task.status = "agent_analyzing"
            candidates = [row for row, _ in vuln_rows]
            sev_rank = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
            candidates.sort(key=lambda r: sev_rank.get(r.severity, 3))
            candidates = candidates[:AGENT_MAX_VULNS]
            if not candidates:
                _log(db, task, "无候选漏洞，跳过 Agent 深度研判")
            else:
                _log(db, task, f"启动 Agent 深度研判：{len(candidates)} 条候选（并发 {AGENT_CONCURRENCY}，步数上限 {AGENT_MAX_STEPS}）")
                try:
                    counts = orchestrator.analyze_vulns(
                        db, candidates, task.workspace_path, task.tech_stack,
                        handle=handle, llm_cfg=llm_cfg,
                        cancel_check=lambda: task.cancel_requested,
                        log_fn=lambda m: _log(db, task, f"  [agent] {m}"))
                    _log(db, task, f"Agent 研判完成：verified={counts.get('verified', 0)} "
                                   f"false_positive={counts.get('false_positive', 0)} "
                                   f"unverified={counts.get('unverified', 0)} error={counts.get('error', 0)}")
                except Exception as e:
                    _log(db, task, f"Agent 研判失败（不影响任务完成）: {e}")
        if _maybe_cancel(db, task, handle):
            return

        # 7.5 Agent 全量审计（根治漏报：不限于 semgrep 命中行，覆盖未授权访问/逻辑/链式漏洞）
        if llm_cfg is not None and task.project_type in ("web", "decompile"):
            audit_ws = task.workspace_path
            if task.project_type == "decompile":
                from app.config import WORKSPACE_DIR
                audit_ws = str(WORKSPACE_DIR / f"task_{task.id}" / "decompiled")
            task.status = "agent_full_audit"
            _log(db, task, "启动 Agent 全量审计（自主遍历全部源码，不依赖静态规则命中）…")
            try:
                existing = [(r.file_path, r.line, r.rule_id)
                            for r in db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()]
                fcounts = orchestrator.full_audit(
                    db, task.id, audit_ws, task.tech_stack,
                    handle=handle, llm_cfg=llm_cfg, existing=existing,
                    cancel_check=lambda: task.cancel_requested,
                    log_fn=lambda m: _log(db, task, f"  [full-audit] {m}"))
                _log(db, task, f"全量审计完成：新增 {fcounts.get('found', 0)} 条 verified，"
                               f"跳过重复 {fcounts.get('skipped', 0)}，落库失败 {fcounts.get('error', 0)}")
            except Exception as e:
                _log(db, task, f"全量审计异常（不影响任务完成）: {e}")
        if _maybe_cancel(db, task, handle):
            return

        # 沙箱生命周期终点：web 任务保留容器供"手工 POC 验证"使用（删除任务时销毁）；
        # 其余类型立即销毁。
        if handle is not None:
            if task.project_type == "web":
                try:
                    task.sandbox_cid = handle.container.id
                    task.sandbox_port = handle.internal_port
                    _log(db, task, "沙箱容器保留中：任务详情页可点击“手动验证”查看漏洞回显，删除任务时将自动销毁")
                except Exception as e:
                    _log(db, task, f"沙箱保留失败: {e}")
            else:
                try:
                    handle.cleanup()
                    _log(db, task, "沙箱容器已销毁")
                except Exception as e:
                    _log(db, task, f"沙箱销毁异常: {e}")
            db.commit()

        # 7. 生成报告（从 DB 读回最新漏洞状态，含 LLM/POC/Agent 结果）
        task.status = "reporting"
        db_vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()
        report_vulns = [{
            "rule_id": r.rule_id, "severity": r.severity, "file_path": r.file_path,
            "line": r.line, "code_snippet": r.code_snippet,
            "llm_is_real": r.llm_is_real, "llm_reason": r.llm_reason,
            "llm_confidence": r.llm_confidence, "poc_payload": r.poc_payload,
            "poc_verified": r.poc_verified, "verify_result": r.verify_result,
            "agent_status": r.agent_status, "agent_evidence": r.agent_evidence,
            "agent_confidence": r.agent_confidence, "agent_reason": r.agent_reason,
            "agent_payload": r.poc_payload,
        } for r in db_vulns]
        if _maybe_cancel(db, task):
            return
        report_path = report.run_report(task, report_vulns)
        task.report_path = report_path
        _log(db, task, f"报告已生成：{report_path}")

        task.status = "completed"
        db.commit()
    except Exception as e:  # 全局兜底
        try:
            task = db.get(Task, task_id)
            if task:
                task.status = "failed"
                task.error_msg = f"任务异常: {e}"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def recover_pending_tasks() -> int:
    """服务启动时恢复中断任务：非终态任务重置为 pending 并重新入队"""
    n = 0
    try:
        db = SessionLocal()
        non_terminal = ("pending", "preprocessing", "sast", "llm_judging", "agent_analyzing",
                        "agent_full_audit", "sandbox_deploying", "poc_verifying", "reporting")
        rows = db.query(Task).filter(Task.status.in_(non_terminal)).all()
        for t in rows:
            if t.status != "pending":
                t.log = (t.log or "") + f"[recover] 服务重启，任务从 {t.status} 重置为 pending\n"
                t.status = "pending"
            task_queue.put(t.id)
            n += 1
        db.commit()
        db.close()
    except Exception as e:  # 恢复失败不阻断启动
        try:
            logging.getLogger("audit-platform.worker").error(f"任务恢复失败: {e}")
        except Exception:
            pass
    return n


def _worker_loop() -> None:
    """单 worker 串行消费任务，任何异常不得导致线程退出。"""
    log = logging.getLogger("audit-platform.worker")
    while True:
        try:
            task_id = task_queue.get()
            _process(task_id)
        except Exception as e:  # noqa: BLE001
            # 异常写服务端日志，不再静默吞掉
            try:
                log.exception(f"worker 处理任务 {task_id} 异常: {e}")
            except Exception:
                pass


def start_worker() -> threading.Thread:
    t = threading.Thread(target=_worker_loop, name="task-worker", daemon=True)
    t.start()
    return t


def enqueue(task_id: int) -> None:
    task_queue.put(task_id)
