"""串行任务队列消费器：完整流水线
preprocess → tech_detect → sast → llm_judge → sandbox → poc → agent → report
支持协作式取消（用户停止）：阶段间检查 cancel_requested，取消时清理沙箱。
任何异常不得导致线程退出。
"""
import json
import logging
import queue
import threading
from datetime import datetime
from pathlib import Path

from app.db import SessionLocal
from app.models import Task, Vulnerability
from app.skills import apk_analyze, decompile, image_baseline, llm_judge, poc, preprocess, report, sast_semgrep, sandbox, tech_detect
from app.agent_settings import agent_settings
from app.agent import orchestrator

task_queue: "queue.Queue[int]" = queue.Queue()


def _log(db, task, msg: str) -> None:
    task.log = (task.log or "") + f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n"
    db.commit()


def _gen_report(db, task, partial: bool = False) -> None:
    """从 DB 已有漏洞数据生成报告（正常收尾，或停止时保留已发现成果）。
    生成前先用 LLM 为缺 title 的漏洞批量生成可读中文名称（很小的 token 开销）。"""
    try:
        db_vulns = db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()
        if not db_vulns:
            if partial:
                _log(db, task, "尚无已发现漏洞，跳过阶段性报告")
            return
        try:
            llm_cfg = llm_judge.get_llm_config(db)
            if llm_cfg is not None and any(not (r.title or "").strip() for r in db_vulns):
                _log(db, task, "为漏洞生成可读中文名称（LLM 批量命名）…")
                n_named = llm_judge.name_vulns(db, task, db_vulns, llm_cfg,
                                               log_fn=lambda m: _log(db, task, m))
                if n_named:
                    _log(db, task, f"已命名 {n_named} 条漏洞")
        except Exception as e:
            _log(db, task, f"漏洞命名失败（不影响报告）: {e}")
        report_vulns = [{
            "rule_id": r.rule_id, "title": r.title, "precondition": r.precondition,
            "severity": r.severity, "file_path": r.file_path,
            "line": r.line, "code_snippet": r.code_snippet,
            "llm_is_real": r.llm_is_real, "llm_reason": r.llm_reason,
            "llm_confidence": r.llm_confidence, "poc_payload": r.poc_payload,
            "poc_verified": r.poc_verified, "verify_result": r.verify_result,
            "agent_status": r.agent_status, "agent_evidence": r.agent_evidence,
            "agent_confidence": r.agent_confidence, "agent_reason": r.agent_reason,
            "agent_payload": r.poc_payload,
        } for r in db_vulns]
        report_path = report.run_report(task, report_vulns)
        task.report_path = report_path
        _log(db, task, f"报告已生成：{report_path}")
    except Exception as e:
        _log(db, task, f"报告生成失败: {e}")


def _maybe_cancel(db, task, handle=None) -> bool:
    """协作式取消检查：已请求停止则立即保留已发现成果并生成阶段性报告，返回 True。
    db.refresh：API 会话写入的 cancel_requested 对本会话的 ORM 缓存不可见
    （expire_on_commit=False），必须强制重读，否则运行中任务的停止请求永远看不到。"""
    try:
        db.refresh(task)
    except Exception:
        pass
    if task.cancel_requested or task.status == "cancelled":
        if handle is not None:
            try:
                handle.cleanup()
            except Exception:
                pass
            _log(db, task, "沙箱容器已销毁")
        task.status = "cancelled"
        task.error_msg = "任务已被停止（已发现结果已保存，可点击“继续任务”续跑）"
        _log(db, task, "收到停止请求：已发现结果立即生成阶段性报告…")
        _gen_report(db, task, partial=True)
        _log(db, task, "任务已停止，结果已保留")
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

        def _cc() -> bool:
            """实时取消检查（供 Agent/全量审计长阶段使用，每次重读数据库）"""
            try:
                db.refresh(task)
            except Exception:
                pass
            return bool(task.cancel_requested)

        # 1. 预处理：APK/镜像/反编译直接分析；zip 解压 + 初筛
        if task.project_type in ("apk", "image", "decompile"):
            task.status = "preprocessing"
            _log(db, task, f"{task.project_type} 文件就绪，跳过解压")
            vuln_dict_map = {}
        else:
            task.status = "preprocessing"
            _log(db, task, "开始预处理：解压源码包…")
            try:
                # 续跑修复：首次运行后 workspace_path 已是解压目录，解压源必须用
                # 始终指向原始上传 zip 的 upload_path，否则续跑报 Is a directory 失败
                src_path = task.upload_path or task.workspace_path
                if Path(src_path).is_dir():
                    _log(db, task, "复用已解压的工作区（续跑，上传原件缺失）")
                    result = {"workspace": str(src_path), "total_size": 0}
                else:
                    result = preprocess.run_preprocess(task, src_path)
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
            # 混合包支持：解压目录内若含编译产物（dll/exe/jar 等），先批量反编译
            # 用户常见场景：上传"整体打包的编译产物 zip"（如 ASP.NET 发布目录），
            # 业务逻辑在 bin/*.dll 里，不能只扫静态资源。此处把它们还原为源码再一起扫。
            try:
                from app.config import DECOMPILE_EXTENSIONS
                emb_bins = [p for p in Path(task.workspace_path).rglob("*")
                            if p.is_file() and p.suffix.lower() in DECOMPILE_EXTENSIONS]
                if emb_bins:
                    _log(db, task, f"检测到包内含编译产物 {len(emb_bins)} 个（含 .dll/.exe/.jar 等），自动反编译…")
                    emb_dec = Path(task.workspace_path) / "decompiled_embedded"
                    emb_dec.mkdir(parents=True, exist_ok=True)
                    emb_ok = 0
                    for b in emb_bins[:100]:  # 上限 100 个，防爆炸
                        try:
                            # 每个二进制独立子目录，避免反编译产物互相覆盖（缓存合并 bug 修复）
                            sub = emb_dec / b.stem[:80].replace(".", "_")
                            sub.mkdir(parents=True, exist_ok=True)
                            d = decompile.decompile(str(b), str(sub),
                                                    lambda m: _log(db, task, m))
                            if d.get("ok"):
                                emb_ok += 1
                        except Exception as e:
                            _log(db, task, f"反编译 {b.name} 异常: {e}")
                    if emb_ok:
                        _log(db, task, f"反编译成功 {emb_ok} 个编译产物，源码已并入扫描目录")
                    else:
                        _log(db, task, "编译产物反编译均失败，仅扫描静态源码")
            except Exception as e:
                _log(db, task, f"混合包反编译检测异常: {e}")
            techs = tech_detect.run_tech_detect_multi(task.workspace_path)
            tech = techs[0] if techs else "unknown"
            task.tech_stack = ",".join(techs) if techs else "unknown"
            _log(db, task, f"识别技术栈：{task.tech_stack}")
            if not techs:
                task.status = "skipped"
                task.error_msg = "未能识别代码语言栈（压缩包内可能不含源码文件），已跳过扫描"
                _log(db, task, "未能识别代码语言栈（压缩包内可能不含源码文件），任务标记为 skipped")
                return
            # 组件指纹识别：审计前先摸清组件/语言分布，供展示与 Agent 参考
            try:
                from app.skills import fingerprint
                fp = fingerprint.fingerprint(task.workspace_path)
                task.fingerprint = json.dumps(fp, ensure_ascii=False)
                _log(db, task, f"组件指纹：{fingerprint.format_fingerprint(fp)}")
            except Exception as e:
                _log(db, task, f"组件指纹识别异常: {e}")
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

        # 落库（续跑兼容：同位置同规则已有记录则复用，不重复落库——
        # 重扫产生的行 agent_status 全为 None，若不复用，下方"跳过已研判"永远不成立，
        # 续跑会重复研判并重复消耗 token）
        existing_rows = {(r.file_path, r.line, r.rule_id): r
                         for r in db.query(Vulnerability).filter(Vulnerability.task_id == task.id).all()}
        vuln_rows = []
        new_cnt = 0
        for v in vulns:
            key = (v["file_path"], v["line"], v["rule_id"])
            row = existing_rows.get(key)
            if row is None:
                row = Vulnerability(
                    task_id=task.id,
                    source={"apk": "apk", "image": "image"}.get(task.project_type, "semgrep"),
                    rule_id=v["rule_id"],
                    severity=v["severity"], file_path=v["file_path"],
                    line=v["line"], code_snippet=v["code_snippet"],
                )
                db.add(row)
                existing_rows[key] = row
                new_cnt += 1
            vuln_rows.append((row, v))
        db.commit()
        if new_cnt < len(vulns):
            _log(db, task, f"续跑兼容：复用已有漏洞记录 {len(vulns) - new_cnt} 条（含研判结果），新落库 {new_cnt} 条")

        # 4. 读取 LLM 配置（供 Agent 深度研判使用）。
        task.status = "llm_judging"
        llm_cfg = llm_judge.get_llm_config(db)
        if task.audit_mode == "static":
            llm_cfg = None
            _log(db, task, "仅静态扫描模式：跳过 Agent 深度研判与全量审计（不消耗 token），即将生成报告")
        elif llm_cfg is None:
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
        elif task.audit_mode == "static":
            handle = None
            _log(db, task, "仅静态扫描模式：跳过沙箱部署与 POC 验证")
        else:
            task.status = "sandbox_deploying"
            _log(db, task, "部署 Docker 沙箱环境…")
            # 多栈任务按识别顺序逐栈尝试部署，任一栈成功即用
            # （修复：tech_stack 是逗号拼接串，直接查配置表必然 miss，多栈任务永远拿不到沙箱）
            handle = None
            for _tech in [t.strip() for t in (task.tech_stack or "").split(",") if t.strip()]:
                h = sandbox.deploy_sandbox(task.workspace_path, _tech, lambda m: _log(db, task, m))
                if h is not None:
                    handle = h
                    _log(db, task, f"沙箱已按 {_tech} 栈部署")
                    break
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

        # 6.5 Agent 深度研判（升级阶段 3）：配置了 LLM 才执行；优先 ERROR/WARNING，最多 agent_max_vulns 条
        st = agent_settings(db)
        if llm_cfg is None:
            _log(db, task, "未配置 LLM，跳过 Agent 深度研判")
        else:
            task.status = "agent_analyzing"
            # 续跑场景：跳过已研判的漏洞（agent_status 非空），不重复消耗 token
            all_rows = [row for row, _ in vuln_rows]
            judged = {r.id for r in all_rows if r.agent_status is not None}
            candidates = [r for r in all_rows if r.agent_status is None]
            if judged:
                _log(db, task, f"续跑：跳过已研判 {len(judged)} 条，仅研判未处理 {len(candidates)} 条")
            sev_rank = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}
            candidates.sort(key=lambda r: sev_rank.get(r.severity, 3))
            candidates = candidates[:st["agent_max_vulns"]]
            if not candidates:
                _log(db, task, "无候选漏洞，跳过 Agent 深度研判")
            else:
                _log(db, task, f"启动 Agent 深度研判：{len(candidates)} 条候选"
                               f"（并发 {st['agent_concurrency']}，步数上限 {st['agent_max_steps']}）")
                try:
                    counts = orchestrator.analyze_vulns(
                        db, candidates, task.workspace_path, task.tech_stack,
                        handle=handle, llm_cfg=llm_cfg,
                        cancel_check=_cc,
                        log_fn=lambda m: _log(db, task, f"  [agent] {m}"),
                        settings=st)
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
                    cancel_check=_cc,
                    fingerprint_json=task.fingerprint,
                    log_fn=lambda m: _log(db, task, f"  [full-audit] {m}"),
                    settings=st)
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
        if _maybe_cancel(db, task):
            return
        _gen_report(db, task, partial=False)

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
