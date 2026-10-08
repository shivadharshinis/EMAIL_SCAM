from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

from app.auth import require_report_access
from app.engines.report import generate_pdf, get_analysis, list_analyses

router = APIRouter()


@router.get("/analyses", dependencies=[Depends(require_report_access)])
async def list_stored_analyses() -> list[dict]:
    summaries = []
    for analysis in list_analyses():
        message = analysis.get("message") or {}
        risk = analysis.get("final_risk") or {}
        ml = analysis.get("ml_detection") or {}
        summaries.append(
            {
                "analysis_id": analysis.get("analysis_id"),
                "filename": analysis.get("filename"),
                "sender": message.get("from") or [],
                "subject": message.get("subject"),
                "prediction": ml.get("prediction"),
                "verdict": risk.get("verdict"),
                "threat_score": risk.get("score"),
                "severity": risk.get("severity"),
                "analyzed_at": analysis.get("analyzed_at"),
            }
        )
    return summaries


@router.get("/analyses/{analysis_id}", dependencies=[Depends(require_report_access)])
async def get_stored_analysis(analysis_id: str) -> dict:
    analysis = get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis ID was not found.")
    return analysis


@router.get("/reports/{analysis_id}", dependencies=[Depends(require_report_access)])
async def download_report(analysis_id: str) -> Response:
    analysis = get_analysis(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis ID was not found.")
    try:
        content = generate_pdf(analysis_id, analysis)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Forensic report generation failed.") from exc
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="email_forensic_report_{analysis_id}.pdf"'},
    )
