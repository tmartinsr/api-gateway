package lu.raiffeisen.gateway.apigateway.filters;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class LoggingGatewayFilterFactory extends AbstractGatewayFilterFactory<LoggingGatewayFilterFactory.Config> {

    final Logger logger = LoggerFactory.getLogger(LoggingGatewayFilterFactory.class);

    public LoggingGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            
            if (config.isPreLogger()) {
                logger.info("Pre GatewayFilter logging: " + config.getBaseMessage());
                logger.info(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
                exchange.getRequest().mutate().header(HttpHeaders.AUTHORIZATION, "Bearer mytoken");
                //exchange.getRequest().getHeaders().set(HttpHeaders.AUTHORIZATION, "Bearer mytoken");
                logger.info(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
            }

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                if (config.isPostLogger()) {
                    logger.info("Post GatewayFilter logging: " + config.getBaseMessage());
                }
            }));
        };
    }

    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;

        public String getBaseMessage() {
            return baseMessage;
        }

        public void setBaseMessage(String baseMessage) {
            this.baseMessage = baseMessage;
        }

        public boolean isPreLogger() {
            return preLogger;
        }

        public void setPreLogger(boolean preLogger) {
            this.preLogger = preLogger;
        }

        public boolean isPostLogger() {
            return postLogger;
        }

        public void setPostLogger(boolean postLogger) {
            this.postLogger = postLogger;
        }

    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("baseMessage", "preLogger", "postLogger");
    }




    
}
