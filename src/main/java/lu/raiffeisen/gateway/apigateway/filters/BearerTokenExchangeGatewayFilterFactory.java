package lu.raiffeisen.gateway.apigateway.filters;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class BearerTokenExchangeGatewayFilterFactory
        extends AbstractGatewayFilterFactory<BearerTokenExchangeGatewayFilterFactory.Config> {
	
	private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(BearerTokenExchangeGatewayFilterFactory.class);

    public static String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static String REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    public static String ISSUER_CONTAINER_TYPE_NONE = "none";
    public static String ISSUER_CONTAINER_TYPE_BY_VALUE = "value";
    public static String ISSUER_CONTAINER_TYPE_HEADER = "header";
    
	@Value("${bearer-token-exchange.auth-server-url}")
    private String authServerBaseUrl;
	
	@Value("${bearer-token-exchange.endpoint-uri}")
    private String tokenEndpointUrl;
	
	@Value("${bearer-token-exchange.client-id}")
    private String clientId;
	
	@Value("${bearer-token-exchange.client-secret}")
    private String clientSecret;
	
	@Value("${bearer-token-exchange.issuer-container-type}")
    private String issuerContainerType;
	
	@Value("${bearer-token-exchange.issuer-container-named}")
    private String issuerContainerName;    

    public BearerTokenExchangeGatewayFilterFactory() {
        super(Config.class);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus)  {
        log.error("Token exchange failed: " + err);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getSubjectIssuer(ServerWebExchange exchange, Config config) {
    	String issConType = (config.getIssuerContainerType() != null ? config.getIssuerContainerType() : this.issuerContainerType);
    	if (issConType.toLowerCase().trim().equals(BearerTokenExchangeGatewayFilterFactory.ISSUER_CONTAINER_TYPE_NONE))
    		return null;
        if (issConType.toLowerCase().trim().equals(BearerTokenExchangeGatewayFilterFactory.ISSUER_CONTAINER_TYPE_BY_VALUE))
        	return (config.getIssuerContainerName() != null ? config.getIssuerContainerName() : this.issuerContainerName);
        if (issConType.toLowerCase().trim().equals(BearerTokenExchangeGatewayFilterFactory.ISSUER_CONTAINER_TYPE_HEADER))
            return this.getSubjectIssuerByHeader(exchange, (config.getIssuerContainerName() != null ? config.getIssuerContainerName() : this.issuerContainerName));
        return null;
    }

    private String getSubjectIssuerByHeader(ServerWebExchange exchange, String headerName) {
        return exchange.getRequest().getHeaders().getFirst(headerName);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
                return this.onError(exchange, "No Authorization header", HttpStatus.UNAUTHORIZED);
            String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (!token.contains("Bearer"))
                return this.onError(exchange, "No bearer authorization token", HttpStatus.UNAUTHORIZED);
            String bearerToken = token.replace("Bearer", "").trim();

            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("client-id", (config.getClientId() != null ? config.getClientId() : this.clientId));
            formData.add("client-secret", (config.getClientSecret() != null ? config.getClientSecret() : this.clientSecret));
            formData.add("grant_type", BearerTokenExchangeGatewayFilterFactory.GRANT_TYPE);
            formData.add("requested_token_type", BearerTokenExchangeGatewayFilterFactory.REQUESTED_TOKEN_TYPE);
            formData.add("subject_token", bearerToken);
            String subjectIssuer = getSubjectIssuer(exchange, config);
            if (subjectIssuer != null)
            	formData.add("subject_issuer", subjectIssuer);
            if (config.getAudience() != null)
            	formData.add("audience", config.getAudience());
            if (config.getScope() != null)
            	formData.add("scope", config.getScope());

            return WebClient.create().post()
                .uri((config.getAuthServerBaseUrl() != null ? config.getAuthServerBaseUrl() : this.authServerBaseUrl) + (config.getTokenEndpointUrl() != null ? config.getTokenEndpointUrl() : this.tokenEndpointUrl))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .exchange()
                .flatMap(response -> {
                    if (!response.statusCode().equals(HttpStatus.OK))
                        return this.onError(exchange, "exchange request failed", HttpStatus.BAD_REQUEST);

                    return response.bodyToMono(String.class)
                        .flatMap(body -> {
                            String accessToken = (String) JsonParserFactory.getJsonParser().parseMap(body).get("access_token");

                            if (accessToken == null || accessToken.trim().isEmpty())
                                return this.onError(exchange, "no token provided", HttpStatus.BAD_REQUEST);

                            exchange.getRequest().mutate().header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

                            return chain.filter(exchange);
                        });
                });
        };
    }

    public static class Config {
    	
        private String authServerBaseUrl;
        private String tokenEndpointUrl;
        private String clientId;
        private String clientSecret;
        private String issuerContainerType;
        private String issuerContainerName;
        private String scope;
        private String audience;

        public String getAudience() {
			return audience;
		}

		public void setAudience(String audience) {
			this.audience = audience;
		}

		public String getScope() {
			return scope;
		}

		public void setScope(String scope) {
			this.scope = scope;
		}

		public String getAuthServerBaseUrl() {
            return authServerBaseUrl;
        }

        public void setAuthServerBaseUrl(String authServerBaseUrl) {
            this.authServerBaseUrl = authServerBaseUrl;
        }

        public String getTokenEndpointUrl() {
            return tokenEndpointUrl;
        }

        public void setTokenEndpointUrl(String tokenEndpointUrl) {
            this.tokenEndpointUrl = tokenEndpointUrl;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getIssuerContainerType() {
            return issuerContainerType;
        }

        public void setIssuerContainerType(String issuerContainerType) {
            this.issuerContainerType = issuerContainerType;
        }

        public String getIssuerContainerName() {
            return issuerContainerName;
        }

        public void setIssuerContainerName(String issuerContainerName) {
            this.issuerContainerName = issuerContainerName;
        }

    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("authServerBaseUrl", "tokenEndpointUrl", "clientId", "clientSecret", "issuerContainerType", "issuerContainerName", "audience", "scope");
    }
    
}
