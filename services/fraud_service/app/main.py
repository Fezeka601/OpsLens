import os
import uuid
import time
import logging

import psycopg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="NexaBank Fraud Service")

DATABASE_URL = os.environ["DATABASE_URL"]

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

logger = logging.getLogger("fraud-service")


class FraudRequest(BaseModel):
    payment_id: uuid.UUID
    amount: float


class FraudResponse(BaseModel):
    payment_id: uuid.UUID
    risk_score: float
    decision: str


@app.get("/health")
def health():
    return {"service": "fraud-service", "status": "healthy"}


@app.post("/fraud/check", response_model=FraudResponse)
def fraud_check(request: FraudRequest):
    trace_id = str(uuid.uuid4())
    start = time.perf_counter()

    try:
        risk_score = min(request.amount / 1000, 100)

        decision = "approved" if risk_score < 80 else "rejected"

        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO fraud_checks
                        (id, payment_id, risk_score, decision)
                    VALUES
                        (%s, %s, %s, %s)
                    """,
                    (
                        uuid.uuid4(),
                        request.payment_id,
                        risk_score,
                        decision,
                    ),
                )

        duration_ms = (time.perf_counter() - start) * 1000

        logger.info(
            {
                "service": "fraud-service",
                "event": "fraud.check.completed",
                "trace_id": trace_id,
                "payment_id": str(request.payment_id),
                "duration_ms": round(duration_ms, 2),
                "decision": decision,
            }
        )

        return FraudResponse(
            payment_id=request.payment_id,
            risk_score=risk_score,
            decision=decision,
        )

    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000

        logger.error(
            {
                "service": "fraud-service",
                "event": "fraud.check.failed",
                "trace_id": trace_id,
                "duration_ms": round(duration_ms, 2),
                "error": str(exc),
            }
        )

        raise HTTPException(
            status_code=500,
            detail="Fraud service database operation failed",
        )