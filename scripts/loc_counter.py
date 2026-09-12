import os

def count_dir(path):
    total_lines = 0
    file_count = 0
    for root, dirs, files in os.walk(path):
        if any(x in root for x in ['.venv', 'node_modules', '.git', '__pycache__', 'tests', 'scripts']):
            continue
        for f in files:
            if f.endswith(('.py', '.ts', '.tsx', '.js', '.jsx', '.css', '.html', '.sql')):
                fp = os.path.join(root, f)
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = len(fh.readlines())
                        total_lines += lines
                        file_count += 1
                except Exception:
                    pass
    return file_count, total_lines

fc_b, loc_b = count_dir('backend/app')
fc_f, loc_f = count_dir('frontend/src')
print(f'backend/app: {fc_b} files, {loc_b} lines')
print(f'frontend/src: {fc_f} files, {loc_f} lines')
print(f'Total prod code: {fc_b + fc_f} files, {loc_b + loc_f} lines')
