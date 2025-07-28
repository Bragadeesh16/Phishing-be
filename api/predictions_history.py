from fastapi import APIRouter 
import Utils


router = APIRouter()

@router.get("/api/predictions-history")
def getPredictions():
    predictions = Utils.get_predictions_from_firestore()
    print(predictions)
    
    return predictions