import os
import math
import time
import uuid
import shutil
import zipfile
from flask import Flask, request, render_template, jsonify, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # អនុញ្ញាតដល់ 500MB

BASE_TMP = "/tmp/zip_splitter_jobs"
os.makedirs(BASE_TMP, exist_ok=True)


def cleanup_old_jobs(max_age_seconds=1800):
    now = time.time()
    for folder in os.listdir(BASE_TMP):
        folder_path = os.path.join(BASE_TMP, folder)
        if os.path.isdir(folder_path):
            if now - os.path.getmtime(folder_path) > max_age_seconds:
                shutil.rmtree(folder_path, ignore_errors=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/split", methods=["POST"])
def split_zip():
    cleanup_old_jobs()

    if "file" not in request.files:
        return jsonify({"error": "សូមជ្រើសរើស File Zip ជាមុនសិន"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "មិនមានឈ្មោះ File ទេ"}), 400

    try:
        parts = int(request.form.get("parts", 4))
        parts = max(2, min(parts, 20))
    except ValueError:
        parts = 4

    mode = request.form.get("mode", "standalone")  # standalone ឬ raw
    job_id = str(uuid.uuid4())[:8]
    job_dir = os.path.join(BASE_TMP, job_id)
    os.makedirs(job_dir, exist_ok=True)

    safe_name = secure_filename(uploaded.filename) or "archive.zip"
    base_title = os.path.splitext(safe_name)[0]
    input_path = os.path.join(job_dir, safe_name)
    uploaded.save(input_path)

    results = []

    try:
        if mode == "standalone":
            if not zipfile.is_zipfile(input_path):
                return jsonify({"error": "File ដែលបញ្ចូលមិនមែនជា .zip ត្រឹមត្រូវទេ"}), 400

            with zipfile.ZipFile(input_path, "r") as zin:
                items = [info for info in zin.infolist() if not info.is_dir()]
                if not items:
                    return jsonify({"error": "មិនមាន File នៅខាងក្នុង Zip នេះទេ"}), 400

                # តម្រៀប File ធំជាងគេមុន ដើម្បីចែកទំហំឱ្យស្មើគ្នាបំផុត
                items.sort(key=lambda x: x.file_size, reverse=True)
                actual_parts = min(parts, len(items))
                bins = [[] for _ in range(actual_parts)]
                bin_sizes = [0] * actual_parts

                for info in items:
                    idx = bin_sizes.index(min(bin_sizes))
                    bins[idx].append(info)
                    bin_sizes[idx] += info.file_size

                for i, group in enumerate(bins, start=1):
                    out_name = f"{base_title}_part{i}.zip"
                    out_path = os.path.join(job_dir, out_name)
                    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zout:
                        for info in group:
                            zout.writestr(info.filename, zin.read(info.filename))

                    size_mb = round(os.path.getsize(out_path) / (1024 * 1024), 2)
                    results.append({
                        "name": out_name,
                        "size_mb": size_mb,
                        "files_count": len(group),
                        "url": f"/download/{job_id}/{out_name}"
                    })
        else:
            # បំបែកជាភាគតភ្ជាប់គ្នា (.001, .002, ...)
            total_size = os.path.getsize(input_path)
            chunk_size = math.ceil(total_size / parts)

            with open(input_path, "rb") as fin:
                for i in range(1, parts + 1):
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    out_name = f"{safe_name}.{i:03d}"
                    out_path = os.path.join(job_dir, out_name)
                    with open(out_path, "wb") as fout:
                        fout.write(chunk)

                    size_mb = round(os.path.getsize(out_path) / (1024 * 1024), 2)
                    results.append({
                        "name": out_name,
                        "size_mb": size_mb,
                        "files_count": None,
                        "url": f"/download/{job_id}/{out_name}"
                    })

        # លុប File ដើមចោលដើម្បីសន្សំទំហំ Server
        os.remove(input_path)
        return jsonify({"parts": results})

    except Exception as e:
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({"error": f"មានបញ្ហាពេលបំបែក File៖ {str(e)}"}), 500


@app.route("/download/<job_id>/<filename>")
def download_file(job_id, filename):
    safe_job = secure_filename(job_id)
    safe_file = secure_filename(filename)
    directory = os.path.join(BASE_TMP, safe_job)
    return send_from_directory(directory, safe_file, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
