import base64
import binascii
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from rules import check_rules
from llm import analyze_with_llm
from privacy import redact

app = FastAPI(title="ScamShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp"}
MAX_IMAGE_BYTES = 4_000_000
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class AnalyzeRequest(BaseModel):
    text: str = ""
    image_base64: Optional[str] = None
    image_mime: Optional[str] = None


@app.get("/health")
def health():
    return {"message": "ScamShield API is running"}


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    # 1. Validate the optional screenshot
    image_bytes = None
    if req.image_base64:
        if req.image_mime not in ALLOWED_MIME:
            raise HTTPException(status_code=400, detail="Unsupported image type.")
        try:
            image_bytes = base64.b64decode(req.image_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="Image data is not valid.")
        if len(image_bytes) > MAX_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail="Image is too large.")

    if not req.text.strip() and not image_bytes:
        raise HTTPException(status_code=400, detail="Please provide a message or a screenshot.")

    # 2. Hide private details in the typed text before anything else touches it
    clean_text, hidden_count = redact(req.text)
    rules = check_rules(clean_text)

    try:
        llm = analyze_with_llm(clean_text, rules["flags"], image_bytes, req.image_mime)

        # For screenshots, run our rule engine on the text the AI read from the image
        if image_bytes:
            extracted, extra_hidden = redact(str(llm.get("extracted_text", "")))
            hidden_count += extra_hidden
            rules = check_rules(clean_text + "\n" + extracted)

        llm_score = max(0, min(100, int(llm.get("risk_score", 0))))
        final_score = round(0.75 * llm_score + 0.25 * rules["score"])
        ai_used = True
    except Exception as e:
        print("LLM error:", e)
        if image_bytes and not clean_text.strip():
            busy = any(w in str(e) for w in ("503", "UNAVAILABLE", "429", "RESOURCE_EXHAUSTED"))
            raise HTTPException(
                status_code=503,
                detail=(
                    "The AI is busy or over its free limit right now. Please try again in a minute."
                    if busy
                    else "The AI could not process this screenshot: " + str(e)[:150]
                ),
            )
        llm = {
            "scam_type": "Unknown",
            "red_flags": [],
            "explanation": "AI analysis was unavailable, so this result uses rule checks only.",
            "what_to_do": ["Do not click links or share OTPs or PINs.",
                           "If unsure, contact the organisation using its official number."],
        }
        final_score = rules["score"]
        ai_used = False

    if final_score < 30:
        verdict = "Safe"
    elif final_score < 55:
        verdict = "Suspicious"
    else:
        verdict = "Dangerous"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "scam_type": llm.get("scam_type", "Unknown"),
        "red_flags": list(dict.fromkeys(rules["flags"] + llm.get("red_flags", []))),
        "explanation": llm.get("explanation", ""),
        "what_to_do": llm.get("what_to_do", []),
        "urls_found": rules["urls"],
        "ai_used": ai_used,
        "privacy_hidden": hidden_count,
    }


# Serve the web page from the same server. This must stay LAST in the file.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")