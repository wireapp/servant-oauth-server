build:
	cabal-fmt -i servant-oauth-server.cabal
	cabal build

tests:
	cabal test --test-show-details=always --test-option=--color

hlint:
	hlint -g -v
