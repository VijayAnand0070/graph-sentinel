# Conference paper (IEEE, 8 pages, A4 two-column)

**Title:** GraphSentinel: A Trustworthy Temporal Graph Neural Network Model for Autonomous
Lateral Movement Detection and Prevention

Deliverables: `D:\GraphSentinel_Conference_Paper.docx` and `D:\GraphSentinel_Conference_Paper.pdf`.

| File | Role |
|---|---|
| `content_v2.py` | the paper: text, tables, equations (OMML), references |
| `build_paper_v1.py` | renderer (header + layout); `assemble_v2.py` splices it with the content |
| `ooxml.py` | minimal WordprocessingML writer (sections, columns, tables, floating figure) |
| `paper_figs.py` | figures, drawn from `artifacts/` |

Rebuild (from this folder):

```bash
python paper_figs.py
python assemble_v2.py && python build_v2.py
python export.py GraphSentinel_Conference_Paper_v2.docx   # Word -> PDF + previews in pages/
python finalize.py                                        # native Word save + PDF to D:\
```

Every number comes from a project artifact (`docs/EVALUATION_REPORT.md`, `artifacts/e2e/lanl_900k/`,
`artifacts/metrics/`, `artifacts/prevention/`, `artifacts/otrf/`, `data/raw/lanl/manifest.json`,
Findings 14, 20, 25-30). References were checked online on 2026-09-29.
Authors: Thillai Nathan B, Vijay Anand J, Nithish Balaji (students) and Anitha R (Professor), Department of
Artificial Intelligence and Machine Learning, Rajalakshmi Engineering College. The paper has no
Acknowledgment section.
