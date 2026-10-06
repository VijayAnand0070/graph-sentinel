"""Write rc_refs.py and rc_eqs.py from the (verified) paper definitions plus report-only additions."""

from pathlib import Path

HERE = Path(__file__).resolve().parent
refs = (HERE / "_paper_refs.txt").read_text(encoding="utf-8")
eqs = (HERE / "_paper_eqs.txt").read_text(encoding="utf-8")

extra_refs = '''
REFERENCES.update({
    "mitre_t1021": 'MITRE ATT&CK, "Remote Services, Technique T1021 \\u2013 Enterprise," The MITRE Corporation. '
                   "[Online]. Available: https://attack.mitre.org/techniques/T1021/ (accessed Sep. 2026).",
    "mitre_t1550": 'MITRE ATT&CK, "Use Alternate Authentication Material, Technique T1550 \\u2013 Enterprise," The '
                   "MITRE Corporation. [Online]. Available: https://attack.mitre.org/techniques/T1550/ (accessed Sep. 2026).",
    "kent2016": 'A. D. Kent, "Cyber security data sources for dynamic network research," in *Dynamic Networks and '
                'Cyber-Security*, N. Adams and N. Heard, Eds. London, U.K.: World Scientific (Imperial College '
                "Press), 2016, pp. 37\\u201365.",
    "un_sdg": 'United Nations General Assembly, "Transforming our world: The 2030 Agenda for Sustainable '
              'Development," Resolution A/RES/70/1, Oct. 2015.',
    "pytorch": "A. Paszke, S. Gross, F. Massa, A. Lerer, J. Bradbury, G. Chanan, T. Killeen, Z. Lin, N. Gimelshein, "
               "L. Antiga, A. Desmaison, A. K\\u00f6pf, E. Yang, Z. DeVito, M. Raison, A. Tejani, S. Chilamkurthy, "
               "B. Steiner, L. Fang, J. Bai, and S. Chintala, \\"PyTorch: An imperative style, high-performance deep "
               "learning library,\\" in *Advances in Neural Information Processing Systems (NeurIPS)*, vol. 32, 2019, "
               "pp. 8024\\u20138035.",
})
'''
(HERE / "rc_refs.py").write_text("# Verified references (see the conference paper) plus report additions.\n" + refs
                                + extra_refs, encoding="utf-8")

header = '''from paper_ooxml import macc, md, mfrac, mfunc, mnary, mr, mrad, msub, msubsup, msup


def v(s):
    return mr(s, "b")


def it(s):
    return mr(s)


def up(s):
    return mr(s, "p")


def sub(b, s):
    return msub(b, s)


'''
extra_eqs = '''
EQUATIONS.update({
    "message": sub(v("\\u03bc"), it("i")) + up("=") + it("h") + md(md(
        sub(v("m"), it("i")) + up("\\u2016") + sub(v("m"), it("j")) + up("\\u2016")
        + sub(macc(v("x"), "\\u0302"), it("k")) + up("\\u2016") + it("\\u03c8") + md(up("\\u0394") + sub(it("t"), it("i")))
        + up("\\u2016") + it("\\u03c8") + md(up("\\u0394") + sub(it("t"), it("j"))), "[", "]")),
    "pathscore": it("S") + up("=0.55\\u2009") + macc(it("r"), "\\u0304") + up("+0.20\\u2009") + it("\\u03bd")
        + up("+0.15\\u2009") + it("\\u03c0") + up("+0.10\\u2009") + it("\\u03b5"),
    "fp": up("FP/10k") + up("=") + msup(up("10"), up("4")) + up("\\u00b7") + mfrac(up("FP"), sub(it("N"), it("b"))),
})
'''
(HERE / "rc_eqs.py").write_text(header + eqs + extra_eqs, encoding="utf-8")
print("written")
