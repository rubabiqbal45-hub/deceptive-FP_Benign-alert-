import os, glob
from docx import Document

DOCS = r'C:\Users\GOGI LAPTOP\OneDrive\Documents'

def fix_docx(path):
    doc = Document(path)
    for p in doc.paragraphs:
        t = p.text
        new = t
        new = new.replace('01/2023 - 12/2023', '07/21/2022 - 06/21/2023')
        if new != t:
            p.text = new
            t = new
        if t.strip() == 'Software Engineering Intern':
            p.text = 'Software Engineering Intern (Virtual)'
        if '1-year Google Software Engineering Internship' in p.text:
            p.text = p.text.replace('1-year Google Software Engineering Internship', '1-year virtual Google Software Engineering Internship')
    doc.save(path)
    print('fixed', os.path.basename(path))

def fix_txt(path):
    with open(path, encoding='utf-8') as f:
        s = f.read()
    s = s.replace('01/2023 - 12/2023', '07/21/2022 - 06/21/2023')
    s = s.replace('Software Engineering Intern\n', 'Software Engineering Intern (Virtual)\n')
    s = s.replace('1-year Google Software Engineering Internship', '1-year virtual Google Software Engineering Internship')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(s)
    print('fixed', os.path.basename(path))

for path in glob.glob(os.path.join(DOCS, 'Ummerubab*.docx')):
    fix_docx(path)
for path in glob.glob(os.path.join(DOCS, 'Ummerubab*.txt')):
    fix_txt(path)
print('DONE')