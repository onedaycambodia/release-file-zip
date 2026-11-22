import os
import re
import json
import math
import time
import uuid
import shutil
import logging
import zipfile
import threading
from urllib.parse import quote

from flask import Flask, request, render_template, jsonify, send_from_directory, abort
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ───────────────────────── Config ─────────────────────────
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 500))
MAX_UNCOMPRESSED_GB = float(os.environ.get("MAX_UNCOMPRESSED_GB", 5))   # ការពារ Zip Bomb
MAX_RATIO = 1000                                                        # compress ratio ខ្ពស់ពេក = គួរឱ្យសង្ស័យ
JOB_TTL_SECONDS = 3600
CHUNK = 1024 * 1024                                                     # 1MB streaming

BASE_TMP = os.environ.get("JOBS_DIR", "/tmp/zip_splitter_jobs")
os.makedirs(BASE_TMP, exist_ok=True)

JOB_ID_RE = re.compile(r"^[a-f0-9]{12}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("zip-splitter")


# ───────────────────────── Job status (file-based, ដំណើរការបានច្រើន worker) ─────────────────────────
class Job:
    """រក្សាស្ថានភាព Job ក្នុង status.json (atomic write) ដើម្បីឱ្យ UI Poll បាន"""

    def __init__(self, job_id):
        self.id = job_id
        self.dir = os.path.join(BASE_TMP, job_id)
        self.path = os.path.join(self.dir, "status.json")
        self.data = {"state": "queued", "progress": 0, "message": "", "parts": [],
                     "warnings": [], "error": None}
        self._last = 0.0
        self._lock = threading.Lock()

    def update(self, force=False, **fields):
        with self._lock:
            self.data.update(fields)
            now = time.time()
            if not force and now - self._last < 0.15:
                return
            self._last = now
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, ensure_ascii=False)
                os.replace(tmp, self.path)
            except OSError:
                log.exception("write status failed")

    def fail(self, message):
        self.update(force=True, state="error", error=message, progress=0)


def read_status(job_id):
    path = os.path.join(BASE_TMP, job_id, "status.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def cleanup_old_jobs():
    now = time.time()
    try:
        for folder in os.listdir(BASE_TMP):
            fp = os.path.join(BASE_TMP, folder)
            if not os.path.isdir(fp):
                continue
            sp = os.path.join(fp, "status.json")
            ref = os.path.getmtime(sp) if os.path.exists(sp) else os.path.getmtime(fp)
            if now - ref > JOB_TTL_SECONDS:
                shutil.rmtree(fp, ignore_errors=True)
    except OSError:
        log.exception("cleanup failed")


# ───────────────────────── Zip helpers ─────────────────────────
def is_unsafe_name(name):
    n = name.replace("\\", "/")
    return n.startswith("/") or re.match(r"^[A-Za-z]:", n) is not None or ".." in n.split("/")


def inspect_zip(path, job):
    """ពិនិត្យ Zip ទាំងមូល (រចនាសម្ព័ន្ធ + CRC ​គ្រប់ File) ហើយប្រាប់ពីបញ្ហាឱ្យច្បាស់"""
    if not zipfile.is_zipfile(path):
        raise ValueError("File នេះមិនមែនជា Zip ត្រឹមត្រូវទេ ឬ Zip ខូច (រកមិនឃើញ End-of-Central-Directory)។ "
                         "សូម Download/ផ្ទុកឡើងម្ដងទៀត។")
    try:
        zin = zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as e:
        raise ValueError(f"Zip ខូច៖ មិនអាចអានបញ្ជី File បាន ({e})។ សូមផ្ទុកឡើងម្ដងទៀត។")

    with zin:
        infos = [i for i in zin.infolist() if not i.is_dir()]
        if not infos:
            raise ValueError("Zip នេះទទេ (គ្មាន File នៅខាងក្នុង)។")

        total = sum(i.file_size for i in infos)
        if total > MAX_UNCOMPRESSED_GB * 1024 ** 3:
            raise ValueError(f"ទំហំក្រោយពេល Extract ធំពេក (>{MAX_UNCOMPRESSED_GB:g} GB) — បដិសេធដើម្បីសុវត្ថិភាព។")
        csize = sum(i.compress_size for i in infos) or 1
        if total / csize > MAX_RATIO and total > 100 * 1024 ** 2:
            raise ValueError("Zip មានសមាមាត្របង្ហាប់ខុសប្រក្រតី (សង្ស័យថាជា Zip Bomb) — បដិសេធ។")

        encrypted = [i.filename for i in infos if i.flag_bits & 0x1]
        if encrypted:
            raise ValueError(f"Zip មាន Password (Encrypted) {len(encrypted)} File — "
                             "សូមដក Password ចេញជាមុនសិន ទើបបំបែកបាន។")

        bad, done = [], 0
        for n, info in enumerate(infos, 1):
            try:
                with zin.open(info, "r") as src:
                    while True:
                        b = src.read(CHUNK)
                        if not b:
                            break
                        done += len(b)
                        job.update(progress=min(done / max(total, 1), 1) * 0.3,
                                   message=f"កំពុងពិនិត្យ {n}/{len(infos)}")
            except zipfile.BadZipFile as e:
                bad.append(f"{info.filename} ({e})")
            except NotImplementedError:
                bad.append(f"{info.filename} (វិធីបង្ហាប់មិនគាំទ្រ)")
            except (EOFError, OSError, ValueError, RuntimeError) as e:
                bad.append(f"{info.filename} ({e.__class__.__name__})")
        if bad:
            shown = "; ".join(bad[:5]) + (f" ... និងផ្សេងទៀត {len(bad) - 5}" if len(bad) > 5 else "")
            raise ValueError(f"Zip ខូច៖ មាន File ខូច {len(bad)}/{len(infos)} — {shown}")
        return infos, total


def split_standalone(path, job, parts, base_title, job_dir):
    infos, _ = inspect_zip(path, job)
    warnings = []
    safe_infos = []
    for i in infos:
        if is_unsafe_name(i.filename):
            warnings.append(f"រំលង File ដែលមាន Path គ្រោះថ្នាក់៖ {i.filename}")
        else:
            safe_infos.append(i)
    if not safe_infos:
        raise ValueError("គ្មាន File ដែលអាចបំបែកបាន (Path ទាំងអស់មិនមានសុវត្ថិភាព)។")

    safe_infos.sort(key=lambda x: x.file_size, reverse=True)
    actual = min(parts, len(safe_infos))
    if actual < parts:
        warnings.append(f"មាន File តែ {len(safe_infos)} ក្នុង Zip ដូច្នេះបំបែកបានត្រឹម {actual} ភាគ។ "
                        "បើចង់បានច្រើនជាងនេះ សូមប្រើ «ភាគតភ្ជាប់គ្នា»។")
    bins = [[] for _ in range(actual)]
    sizes = [0] * actual
    for info in safe_infos:
        k = sizes.index(min(sizes))
        bins[k].append(info)
        sizes[k] += info.file_size

    grand = max(sum(sizes), 1)
    done, results = 0, []
    with zipfile.ZipFile(path, "r") as zin:
        for idx, group in enumerate(bins, 1):
            out_name = f"{base_title}_part{idx}.zip"
            out_path = os.path.join(job_dir, out_name)
            with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as zout:
                for info in group:
                    zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = info.external_attr
                    with zin.open(info, "r") as src, zout.open(zi, "w", force_zip64=True) as dst:
                        while True:
                            b = src.read(CHUNK)
                            if not b:
                                break
                            dst.write(b)
                            done += len(b)
                            job.update(progress=0.3 + 0.7 * min(done / grand, 1),
                                       message=f"កំពុងបង្កើតភាគទី {idx}/{actual}")
            results.append(make_result(job.id, out_name, out_path, len(group)))
    return results, warnings


def split_raw(path, job, parts, safe_name, job_dir):
    inspect_zip(path, job)  # ធានាថា Zip ល្អ មុនបំបែក
    total = os.path.getsize(path)
    if total == 0:
        raise ValueError("File ទទេ (0 byte)។")
    parts = min(parts, total)
    chunk_size = math.ceil(total / parts)
    done, results = 0, []
    with open(path, "rb") as fin:
        for i in range(1, parts + 1):
            out_name = f"{safe_name}.{i:03d}"
            out_path = os.path.join(job_dir, out_name)
            remaining = chunk_size
            written = 0
            with open(out_path, "wb") as fout:
                while remaining > 0:
                    b = fin.read(min(CHUNK, remaining))
                    if not b:
                        break
                    fout.write(b)
                    remaining -= len(b)
                    written += len(b)
                    done += len(b)
                    job.update(progress=0.3 + 0.7 * (done / total),
                               message=f"កំពុងបង្កើតភាគទី {i}/{parts}")
            if written == 0:
                os.remove(out_path)
                break
            results.append(make_result(job.id, out_name, out_path, None))
    return results, []


def make_result(job_id, name, path, files_count):
    return {
        "name": name,
        "size_mb": round(os.path.getsize(path) / (1024 * 1024), 2),
        "files_count": files_count,
        "url": f"/download/{job_id}/{quote(name)}",
    }


def run_job(job_id, input_path, safe_name, parts, mode):
    job = Job(job_id)
    job.data.update(state="processing", progress=0, message="កំពុងចាប់ផ្តើម...")
    job.update(force=True)
    job_dir = job.dir
    try:
        base_title = os.path.splitext(safe_name)[0]
        if mode == "raw":
            results, warnings = split_raw(input_path, job, parts, safe_name, job_dir)
        else:
            results, warnings = split_standalone(input_path, job, parts, base_title, job_dir)
        try:
            os.remove(input_path)  # សន្សំទំហំ Server
        except OSError:
            pass
        job.update(force=True, state="done", progress=1, parts=results,
                   warnings=warnings, message="រួចរាល់")
    except ValueError as e:
        job.fail(str(e))
    except MemoryError:
        job.fail("Server អស់ Memory ពេលដំណើរការ File នេះ។")
    except OSError as e:
        log.exception("os error")
        job.fail(f"បញ្ហា Disk/File ក្នុង Server៖ {e.strerror or e}")
    except Exception as e:  # noqa
        log.exception("unexpected error")
        job.fail(f"មានបញ្ហាមិនរំពឹងទុក៖ {e.__class__.__name__}")
    finally:
        # លុប output ដែលនៅសល់ ប្រសិនបើបរាជ័យ
        st = read_status(job_id)
        if st and st.get("state") == "error":
            for f in os.listdir(job_dir):
                if f != "status.json":
                    try:
                        os.remove(os.path.join(job_dir, f))
                    except OSError:
                        pass


# ───────────────────────── Routes ─────────────────────────
@app.route("/")
def index():
    return render_template("index.html", max_mb=MAX_UPLOAD_MB)


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.route("/split", methods=["POST"])
def split_zip():
    cleanup_old_jobs()

    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "សូមជ្រើសរើស File Zip ជាមុនសិន"}), 400
    if not uploaded.filename:
        return jsonify({"error": "មិនមានឈ្មោះ File ទេ"}), 400

    try:
        parts = max(2, min(int(request.form.get("parts", 4)), 20))
    except (TypeError, ValueError):
        parts = 4
    mode = request.form.get("mode", "standalone")
    if mode not in ("standalone", "raw"):
        mode = "standalone"

    job_id = uuid.uuid4().hex[:12]
    job_dir = os.path.join(BASE_TMP, job_id)
    os.makedirs(job_dir, exist_ok=True)

    name = secure_filename(uploaded.filename) or "archive.zip"
    if not name.lower().endswith(".zip"):
        name += ".zip"
    input_path = os.path.join(job_dir, "input_" + name)

    try:
        uploaded.save(input_path)
        size = os.path.getsize(input_path)
        if size == 0:
            raise ValueError("File ដែលផ្ទុកឡើងទទេ (0 byte)។ អាចជា Upload មិនទាន់ចប់។")
        with open(input_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] != b"PK":
            raise ValueError("File នេះមិនមែនជា Zip ទេ (Header មិនត្រូវ) ឬខូចតាំងពីដើម។")
    except ValueError as e:
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({"error": str(e)}), 400
    except OSError as e:
        shutil.rmtree(job_dir, ignore_errors=True)
        log.exception("save failed")
        return jsonify({"error": f"រក្សាទុក File មិនបាន៖ {e.strerror or e}"}), 500

    Job(job_id).update(force=True, state="queued", message="កំពុងរង់ចាំ...")
    t = threading.Thread(target=run_job, args=(job_id, input_path, name, parts, mode), daemon=True)
    t.start()
    return jsonify({"job_id": job_id}), 202


@app.route("/status/<job_id>")
def status(job_id):
    if not JOB_ID_RE.match(job_id):
        return jsonify({"error": "Job ID មិនត្រឹមត្រូវ"}), 400
    st = read_status(job_id)
    if st is None:
        return jsonify({"error": "រកមិនឃើញ Job (អាចផុតកំណត់ ឬ Server Restart)"}), 404
    return jsonify(st)


@app.route("/download/<job_id>/<path:filename>")
def download_file(job_id, filename):
    if not JOB_ID_RE.match(job_id):
        abort(400)
    safe_file = secure_filename(filename)
    if not safe_file or safe_file == "status.json":
        abort(404)
    directory = os.path.join(BASE_TMP, job_id)
    if not os.path.isfile(os.path.join(directory, safe_file)):
        abort(404)
    resp = send_from_directory(directory, safe_file, as_attachment=True)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ───────────────────────── Error handlers (JSON ជានិច្ច) ─────────────────────────
@app.errorhandler(RequestEntityTooLarge)
def too_large(_e):
    return jsonify({"error": f"File ធំពេក! អនុញ្ញាតអតិបរមា {MAX_UPLOAD_MB} MB"}), 413


@app.errorhandler(HTTPException)
def http_error(e):
    msgs = {400: "សំណើមិនត្រឹមត្រូវ", 404: "រកមិនឃើញ (File ប្រហែលផុតកំណត់ហើយ)", 405: "Method មិនអនុញ្ញាត"}
    return jsonify({"error": msgs.get(e.code, e.description or "មានបញ្ហា")}), e.code


@app.errorhandler(Exception)
def server_error(e):
    log.exception("unhandled")
    return jsonify({"error": "Server មានបញ្ហា សូមព្យាយាមម្ដងទៀត"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
