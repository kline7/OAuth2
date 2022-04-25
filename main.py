from fastapi import FastAPI, Depends, Request
from oauth import auth_token, create_token, Token, OAuth2ClientRequestForm

app = FastAPI()

@app.get("/")
def read_root(client=Depends(auth_token)):
    return {"client_secret": client}

@app.post("/auth/token", response_model=Token)
async def auth_token(
    request: Request,
    form: OAuth2ClientRequestForm = Depends()
):
    return create_token(request, form)
