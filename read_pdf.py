from pypdf import PdfReader

reader = PdfReader('EvaluacionPractica.pdf')
for i, page in enumerate(reader.pages):
    print(f'--- Página {i+1} ---')
    print(page.extract_text())
