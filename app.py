from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
from techcombank import *
from api_response import APIResponse


app = FastAPI()
@app.get("/")
def read_root():
    return {"Hello": "World"}
class LoginDetails(BaseModel):
    username: str
    password: str
    account_number: str
    
@app.post('/login', tags=["login"])
def login_api(input: LoginDetails):
        techcombank = Techcombank(input.username, input.password, input.account_number,"","")
        result = techcombank_login(techcombank)
        return APIResponse.json_format(result)

@app.post('/get_balance', tags=["get_balance"])
def get_balance_api(input: LoginDetails):
        techcombank = Techcombank(input.username, input.password, input.account_number,"","")
        balance = sync_balance_techcombank(techcombank)
        return APIResponse.json_format(balance)
    
class Transactions(BaseModel):
    username: str
    password: str
    account_number: str
    from_date: str
    to_date: str
    
@app.post('/get_transactions', tags=["get_transactions"])
def get_transactions_api(input: Transactions):
        techcombank = Techcombank(input.username, input.password, input.account_number,"","")
        transactions = sync_techcombank(techcombank,input.from_date,input.to_date)
        return APIResponse.json_format(transactions)
    
if __name__ == "__main__":
    uvicorn.run(app ,host='0.0.0.0', port=3000)