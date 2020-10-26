<?php


class Request
{
    protected $awsKey;
    protected $awsSecret;
    protected $accessToken;
    public $host = 'sellingpartnerapi-na.amazon.com';
    public $region = 'us-east-1';
    protected $uri;
    protected $requestUrl;
    public $userAgent='SomeApi/1.5 (Language PHP/7.2;)';

    /**
     * Request constructor.
     * @param $awsKey
     * @param $awsSecret
     * @param $accessToken
     */
    public function __construct($awsKey, $awsSecret, $accessToken){
        $this->awsKey=$awsKey;
        $this->awsSecret=$awsSecret;
        $this->accessToken=$accessToken;
    }

    /**
     * Send request
     * @param $uri
     * @param string $method
     * @param array $data
     * @return array
     */
    public function send($uri, $method='GET', $data=[]){
        $this->requestUrl='https://'.$this->host.$uri;
        $headers = $this->signatureHeaders($this->host, $uri, $this->requestUrl,
            $this->awsKey, $this->awsSecret, $this->accessToken, $this->region, 'execute-api',
            $method, '', TRUE);

        return $this->callAPI($this->requestUrl, $method, $headers, $data, TRUE);
    }

    /**
     * AWS4 Signature & Headers
     * @param $host
     * @param $uri
     * @param $requestUrl
     * @param $accessKey
     * @param $secretKey
     * @param $accessToken
     * @param $region
     * @param $service
     * @param $httpRequestMethod
     * @param $data
     * @param bool $debug
     * @return array headers
     */
    private function signatureHeaders($host, $uri, $requestUrl, $accessKey, $secretKey, $accessToken,
                                      $region, $service, $httpRequestMethod, $data, $debug = TRUE) : array{

        $terminationString	= 'aws4_request';
        $algorithm 		= 'AWS4-HMAC-SHA256';
        $phpAlgorithm 		= 'sha256';
        $canonicalURI		= $uri;
        $canonicalQueryString	= '';
        $signedHeaders		= 'host;user-agent;x-amz-access-token;x-amz-date';

        $currentDateTime = new \DateTime('UTC');
        $reqDate = $currentDateTime->format('Ymd');
        $reqDateTime = $currentDateTime->format('Ymd\THis\Z');

        // Create signing key
        $kSecret = $secretKey;
        $kDate = hash_hmac($phpAlgorithm, $reqDate, 'AWS4' . $kSecret, true);
        $kRegion = hash_hmac($phpAlgorithm, $region, $kDate, true);
        $kService = hash_hmac($phpAlgorithm, $service, $kRegion, true);
        $kSigning = hash_hmac($phpAlgorithm, $terminationString, $kService, true);

        // Create canonical headers
        $canonicalHeaders = array();
        //$canonicalHeaders[] = 'content-type:application/x-www-form-urlencoded';
        $canonicalHeaders[] = 'host:' . $host;
        $canonicalHeaders[] = 'user-agent:' . 'SomeApi/1.5';
        $canonicalHeaders[] = 'x-amz-access-token:' . $accessToken;
        //$canonicalHeaders[] = 'x-amz-date:' . $reqDateTime;
        $canonicalHeadersStr = implode("\n", $canonicalHeaders);

        // Create request payload
        //$requestHasedPayload = hash($phpAlgorithm, $data);

        // Create canonical request
        $canonicalRequest = array();
        $canonicalRequest[] = $httpRequestMethod;
        $canonicalRequest[] = $canonicalURI;
        $canonicalRequest[] = $canonicalQueryString;
        $canonicalRequest[] = $canonicalHeadersStr . "\n";
        $canonicalRequest[] = $signedHeaders;
        //$canonicalRequest[] = $requestHasedPayload;
        $requestCanonicalRequest = implode("\n", $canonicalRequest);
        //$requestHasedCanonicalRequest = hash($phpAlgorithm, utf8_encode($requestCanonicalRequest));
        $requestHasedCanonicalRequest = hash($phpAlgorithm, $requestCanonicalRequest);
        if($debug){
            echo "Canonical to string:\n";
            echo $requestCanonicalRequest."\n";
            echo "\n";
        }

        // Create scope
        $credentialScope = array();
        $credentialScope[] = $reqDate;
        $credentialScope[] = $region;
        $credentialScope[] = $service;
        $credentialScope[] = $terminationString;
        $credentialScopeStr = implode('/', $credentialScope);

        // Create string to signing
        $stringToSign = array();
        $stringToSign[] = $algorithm;
        $stringToSign[] = $reqDateTime;
        $stringToSign[] = $credentialScopeStr;
        $stringToSign[] = $requestHasedCanonicalRequest;
        $stringToSignStr = implode("\n", $stringToSign);
        if($debug){
            echo "String to Sign:\n";
            echo $stringToSignStr."\n";
            echo "\n";
        }

        // Create signature
        $signature = hash_hmac($phpAlgorithm, $stringToSignStr, $kSigning);

        // Create authorization header
        $authorizationHeader = array();
        $authorizationHeader[] = 'Credential=' . $accessKey . '/' . $credentialScopeStr;
        $authorizationHeader[] = 'SignedHeaders=' . $signedHeaders;
        $authorizationHeader[] = 'Signature=' . ($signature);
        $authorizationHeaderStr = $algorithm . ' ' . implode(', ', $authorizationHeader);


        // Request headers
        $headers = array();
        $headers[] = 'authorization:'.$authorizationHeaderStr;
        //$headers[] = 'content-length:'.strlen($data);
        //$headers[] = 'content-type: application/x-www-form-urlencoded';
        $headers[] = 'host: ' . $host;
        $headers[] = 'user-agent: ' . $this->userAgent;
        $headers[] = 'x-amz-access-token: ' . $accessToken;
        $headers[] = 'x-amz-date: ' . $reqDateTime;

        return $headers;
    }

    /**
     * Call SellingPartnerAPI (SP-API)
     * @param $requestUrl
     * @param $httpRequestMethod
     * @param $headers
     * @param $data
     * @param bool $debug
     * @return array
     */
    private function callAPI($requestUrl, $httpRequestMethod, $headers, $data, $debug=TRUE) : array{
        // Execute the call
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $requestUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 30,
            //CURLOPT_POST => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => $httpRequestMethod,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_VERBOSE => 0,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => 0,
            CURLOPT_HEADER => false,
            CURLINFO_HEADER_OUT=>true,
            CURLOPT_HTTPHEADER => $headers,
        ));

        $response = curl_exec($curl);
        $err = curl_error($curl);
        $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        if($debug){
            $headers = curl_getinfo($curl, CURLINFO_HEADER_OUT);
            echo "Request Headers:\n";
            echo $headers."\n";
            echo "\n";
        }

        curl_close($curl);

        if ($err) {
            if($debug){
                echo "Error:" . $responseCode . "\n";
                echo $err."\n";
                echo "\n";
            }
        } else {
            if($debug){
                echo "Response:" . $responseCode . "\n";
                echo $response."\n";
                echo "\n";
            }
        }

        return array(
            "responseCode" => $responseCode,
            "response" => $response,
            "error" => $err
        );
    }

}
