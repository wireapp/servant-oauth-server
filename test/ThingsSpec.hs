{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module ThingsSpec where

import Control.Lens
import Control.Monad (liftM)
import Control.Monad.Error.Class (MonadError, catchError, throwError)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Trans.Except (ExceptT, throwE)
import Crypto.JWT (StringOrURI, defaultJWTValidationSettings)
import Crypto.Random.Types (MonadRandom, getRandomBytes)
import Data.Aeson
import qualified Data.Aeson.Lens as A
import Data.Maybe (fromJust)
import Data.Proxy
import Data.String
import Data.String.Conversions (cs)
import Data.Text
import Network.Wai
import Network.Wai.Test (SRequest (..), simpleBody)
import Servant.API
import Servant.OAuth.Grants (OAuthGrantCodePKCE (OAuthGrantCodePKCE), OAuthGrantOpaqueAssertion (..), OpaqueToken (..))
import Servant.OAuth.Grants.Facebook
import Servant.OAuth.JWT
import Servant.OAuth.ResourceServer
import Servant.OAuth.TokenServer
import Servant.OAuth.TokenServer.Types
import Servant.Server
import Test.Hspec hiding (pending)
import Test.Hspec.Wai
import Test.Hspec.Wai.Matcher
import Web.FormUrlEncoded (ToForm (toForm), urlEncodeForm)

------------------------------

-- | generated with 'mkTestJWTSignSettings'
testJWTSignSettings :: JWTSignSettings
Just testJWTSignSettings =
  decode "{\"jwtDuration\":5,\"jwtInitialClaims\":{},\"jwtSignKey\":{\"crv\":\"Ed25519\",\"d\":\"ZfSXWx4QCq4mQW_lPOXGvcqfEy6757Q2s9gWK2YbV88\",\"key_ops\":[\"sign\",\"verify\"],\"kid\":\"RHKw2tjb43P5mMab0m_xpYbNpAaiXROLdaOR8so4joo\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"Rm-3PqAInCgSjdlqWJz1RKADlIajHLa5So-uY4R95EU\"}}"

testJWTSettings :: JWTSettings
testJWTSettings =
  JWTSettings
    (SomeJWKResolver (jwtSignKey testJWTSignSettings))
    (defaultJWTValidationSettings (== tokenPayload))

tokenPayload :: IsString s => s
tokenPayload = "..."

------------------------------

newtype AppM a = AppM {runAppM :: Handler a}
  deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadRandom AppM where
  getRandomBytes =
    -- TODO: why isn't this catching?  are we just adding a determinstic digest instead of the ec25519 signature?
    undefined

instance MonadError ServerError AppM where
  throwError = AppM . Handler . throwE
  catchError (AppM action) handler = AppM (action `catchError` (runAppM . handler))

------------------------------

type API =
  "fb" :> FacebookAPI
    :<|> "pkce" :> PkceAPI

type FacebookAPI =
  "oauth" :> "access_token" :> OAuthTokenEndpoint' '[JSON] OAuthGrantFacebookAssertion
    :<|> "login" :> AuthRequired (ClaimSub Text) :> Get '[JSON] Text
    :<|> "login-optional" :> AuthOptional (ClaimSub Text) :> Get '[JSON] Text

type PkceAPI =
  "oauth" :> "token" :> OAuthTokenEndpoint' '[FormUrlEncoded] OAuthGrantCodePKCE

app :: IO Application
app =
  pure . serveWithContext (Proxy @API) (testJWTSettings :. EmptyContext) $ api
  where
    api :: ServerT API Handler
    api = fbAPI :<|> pkceAPI

    fbAPI :: ServerT FacebookAPI Handler
    fbAPI =
      runAppM . tokenEndpointNoRefresh testJWTSignSettings tokenHandlerFB
        :<|> runAppM . resourceHandler . Just
        :<|> runAppM . resourceHandler

    pkceAPI :: ServerT PkceAPI Handler
    pkceAPI = runAppM . tokenEndpointNoRefresh testJWTSignSettings tokenHandlerPKCE

tokenHandlerFB :: Monad m => OAuthGrantFacebookAssertion -> m (ClaimSub Text)
tokenHandlerFB = pure . ClaimSub . cs . show

-- | This is a dummy handler for testing
-- A real handler usually takes:
--   [ ] grant_type    :: Denotes the flow you are using. For Authorization Code (PKCE) use authorization_code.
--   [ ] client_id     :: Your application's Client ID.
--   [x] code_verifier :: Cryptographically random key that was used to generate the code_challenge passed to /authorize
--   [x] code          :: The Authorization Code received from the initial /authorize call.
--   [ ] redirect_uri  :: This is required only if it was set at the GET /authorize endpoint. The values must match.
-- as parameters.
-- In this handler the code_verifier should be verified against the code_challenge created in the /authorize call.
-- Handler should respond with an ID token and an access token.
-- At this stage this lib does not provide a `GET /authorize` endpoint AFAICT.
tokenHandlerPKCE :: Monad m => OAuthGrantCodePKCE -> m (ClaimSub Text)
tokenHandlerPKCE = pure . ClaimSub . cs . show

resourceHandler :: Maybe (ClaimSub Text) -> AppM Text
resourceHandler = pure . cs . encode

------------------------------

spec :: Spec
spec = with app $ do
  describe "fetch token" $ do
    it "success case" $ do
      let reqbody :: OAuthGrantFacebookAssertion
          reqbody = OAuthGrantOpaqueAssertion (OpaqueToken tokenPayload)

      -- TODO: `200 {matchBody = bodyEquals $ encode (OAuthTokenSuccess (CompactJWT tokenPayload) 5 Nothing)}`
      -- (but that requires reproducible randomness in the token server.)
      request "POST" "fb/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
        `shouldRespondWith` 200

    it "failure case" $ do
      pending

  describe "PKCE flow" $ do
    it "success case" $ do
      let reqBody :: OAuthGrantCodePKCE
          reqBody = OAuthGrantCodePKCE "foo" "bar"
      request "POST" "pkce/oauth/token" [("Content-type", "application/x-www-form-urlencoded")] (urlEncodeForm . toForm $ reqBody)
        `shouldRespondWith` 200

    it "failure case" $ do
      pending

  describe "present token to resource server" $ do
    it "success case" $ do
      resp <- do
        let reqbody = OAuthGrantOpaqueAssertion (OpaqueToken tokenPayload) :: OAuthGrantFacebookAssertion
        request "POST" "fb/oauth/access_token" [("Content-type", "application/json")] (encode reqbody)
      let Just token = decode @Value (simpleBody resp) >>= (^? A.key ("access_token" :: Key) . A._String)
      request "GET" "fb/login" [("Content-type", "application/json"), ("Authorization", "Bearer " <> cs token)] mempty
        `shouldRespondWith` 200 {matchBody = bodyEquals . cs . show $ "\"OAuthGrantOpaqueAssertion (OpaqueToken \\\"...\\\")\""}

    it "failure case" $ do
      pending
