import sys

file1 = r'c:\Users\prana\OneDrive\Desktop\SURAKSHA\templates\web_scan.html'
with open(file1, 'r', encoding='utf-8') as f:
    content1 = f.read()

old1 = '''                {% elif scan_data.https_enabled %}
                    <span class="badge mt-1 bg-success-subtle text-success"><i class="bi bi-lock-fill me-1"></i>Transport Encrypted</span>
                {% else %}
                    <span class="badge mt-1 bg-danger-subtle text-danger"><i class="bi bi-unlock-fill me-1"></i>Plaintext Unencrypted</span>'''

new1 = '''                {% elif scan_data.https_enabled == "Failed" %}
                    <span class="badge mt-1 bg-warning-subtle text-warning"><i class="bi bi-exclamation-triangle me-1"></i>Check Failed</span>
                {% elif scan_data.https_enabled %}
                    <span class="badge mt-1 bg-success-subtle text-success"><i class="bi bi-lock-fill me-1"></i>Encrypted / HTTPS</span>
                {% else %}
                    <span class="badge mt-1 bg-danger-subtle text-danger"><i class="bi bi-unlock-fill me-1"></i>Plaintext / Unencrypted</span>'''

if old1 in content1:
    content1 = content1.replace(old1, new1)
    with open(file1, 'w', encoding='utf-8') as f:
        f.write(content1)
    print('Updated web_scan.html')
else:
    print('old1 not found in web_scan.html')

file2 = r'c:\Users\prana\OneDrive\Desktop\SURAKSHA\templates\report_details.html'
with open(file2, 'r', encoding='utf-8') as f:
    content2 = f.read()

old2 = '''                    {% elif details.scan_data.https_enabled %}
                        <span class="badge bg-success-subtle"><i class="bi bi-lock-fill me-1"></i> Secured (HTTPS)</span>
                    {% else %}
                        <span class="badge bg-danger-subtle"><i class="bi bi-unlock-fill me-1"></i> Plaintext (HTTP)</span>'''

new2 = '''                    {% elif details.scan_data.https_enabled == "Failed" %}
                        <span class="badge bg-warning-subtle"><i class="bi bi-exclamation-triangle me-1"></i> Check Failed</span>
                    {% elif details.scan_data.https_enabled %}
                        <span class="badge bg-success-subtle"><i class="bi bi-lock-fill me-1"></i> Encrypted / HTTPS</span>
                    {% else %}
                        <span class="badge bg-danger-subtle"><i class="bi bi-unlock-fill me-1"></i> Plaintext / Unencrypted</span>'''

if old2 in content2:
    content2 = content2.replace(old2, new2)
    with open(file2, 'w', encoding='utf-8') as f:
        f.write(content2)
    print('Updated report_details.html')
else:
    print('old2 not found in report_details.html')
