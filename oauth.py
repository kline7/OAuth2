import base64
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2
from fastapi.param_functions import Form
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel, OAuthFlowClientCredentials
from fastapi.security.utils import get_authorization_scheme_param
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from pydantic import BaseModel
from jose import jwt

# To get a string like this run:
# openssl rand -hex 32
# SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_clients_db = {
    "johnsmith": {
        'secret': "John smith",
	'active': True,
    },
    "janedoe": {
	'secret': "Jane Doe",
	'active': True,
    }
}


def generate_client_credentials(audience: str, scopes: List[str]=None):
    data = dict(
        client_id=str(uuid4()),
        client_secret=secrets.token_hex(32),
	scopes=scopes
    )
    # Save to db, keyed using audience
    return data



class Token(BaseModel):
    access_token: str
    token_type: str='bearer'



class OAuth2ClientRequestForm:

    def __init__(
        self,
        grant_type: str = Form(None, regex="client_credentials"),
        scope: str = Form("api"),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        self.grant_type = grant_type
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret



class OAuth2ClientBearer(OAuth2):

    def __init__(
        self,
        tokenUrl: str,
        scheme_name: Optional[str]=None,
        scopes: Optional[Dict[str, str]]=None,
        description: Optional[str]=None,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(clientCredentials={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
	        scheme_name=scheme_name,
	        description=description,
	    )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
	                status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
		            headers={"WWW-Authenticate": "Bearer"},
		        )
            else:
                return None
        return param

oauth2 = OAuth2ClientBearer(tokenUrl="auth/token")


def authenticate(id: str, secret: str):
    try:
        client = fake_clients_db[id]
        return client and client['secret'] == secret
    except:
        return None


def create_token(
    request: Request,
    form: OAuth2ClientRequestForm
    ) -> Token:
    id = ""
    secret = ""

    if form.client_id and form.client_secret:
        id = form.client_id
        secret = form.client_secret
    else:
        auth_type, value = request.headers['authorization'].split()
        if auth_type.lower() == "basic":
            id, secret = base64.b64decode(value).decode('utf-8').split(":")

    user = authenticate(id, secret)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect client credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    to_encode = {
        'iss': f'https://{request.url.hostname}',
        'sub': id,
        'iat': datetime.utcnow(),
        'scope': ','.join(form.scopes),
        'exp': datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    encoded_jwt = jwt.encode(to_encode, secret, algorithm=ALGORITHM)
    return Token(access_token=encoded_jwt)


async def auth_token(token: str=Depends(oauth2)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
       # TODO: use client to look up secret
       subject_client = jwt.get_unverified_claims(token)
       print(f'Subject: {subject_client}')
       subject_id = subject_client['sub']
       client = fake_clients_db[subject_id]
       print(f'Client: {client}')
       # TODO: check to see if client exists
       secret = client['secret']
       payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
       print(f'Payload: {payload}')
       id: str = payload.get("sub", None)
       if id is None:
           raise credentials_exception
    except BaseException as err:  # JWTError
        raise err
        # raise credentials_exception

    client = fake_clients_db[id]
    if client and client['active']:
        return client
    else:
        raise HTTPException(status_code=400, detail="Inactive client")
