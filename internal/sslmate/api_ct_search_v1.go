package sslmate

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
)

type CTSearchV1APIService service

type ApiGetIssuancesRequest struct {
	ctx        context.Context
	ApiService *CTSearchV1APIService
	domain     string
	apiKey     string
}

func (r ApiGetIssuancesRequest) Execute() (*[]IssuanceObject, *http.Response, error) {
	return r.ApiService.GetIssuancesExecute(r)
}

/*
GetIssuances List all unexpired certificate issuances for a domain.

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param domain Domain name
	@return ApiGetCertificateRequest
*/
func (a *CTSearchV1APIService) GetIssuances(ctx context.Context, domain string, apiKey string) ApiGetIssuancesRequest {
	return ApiGetIssuancesRequest{
		ApiService: a,
		ctx:        ctx,
		domain:     domain,
		apiKey:     apiKey,
	}
}

func (a *CTSearchV1APIService) GetIssuancesExecute(r ApiGetIssuancesRequest) (*[]IssuanceObject, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *[]IssuanceObject
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "CTSearchV1APIService.GetIssuances")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/issuances"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	parameterAddToHeaderOrQuery(localVarQueryParams, "domain", r.domain, "")
	parameterAddToHeaderOrQuery(localVarQueryParams, "include_subdomains", "true", "")
	parameterAddToHeaderOrQuery(localVarQueryParams, "match_wildcards", "true", "")
	parameterAddToHeaderOrQuery(localVarQueryParams, "expand", "cert_der", "")
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set "Authorization: Bearer" header with the API key if it is not empty
	if r.apiKey != "" {
		localVarHeaderParams["Authorization"] = "Bearer " + r.apiKey
	}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode >= 400 && localVarHTTPResponse.StatusCode < 600 {
			var v ErrorObject
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}