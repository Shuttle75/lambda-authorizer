package nl.theguild.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import nl.theguild.lambda.model.AuthorizerResponse;
import nl.theguild.lambda.model.aws.PolicyDocument;
import nl.theguild.lambda.model.aws.Statement;
import nl.theguild.lambda.util.JwtUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Authorizer implements RequestHandler<APIGatewayProxyRequestEvent, AuthorizerResponse> {

    public AuthorizerResponse handleRequest(APIGatewayProxyRequestEvent request, Context context) {
        Map<String, String> headers = request.getHeaders();

        Objects.requireNonNull(headers, "No headers");
        Objects.requireNonNull(headers.get("authorization"), "No token");

        String authorization = headers.get("authorization");

        String jwt = authorization.substring("Bearer ".length());

        Map<String, String> ctx = new HashMap<>();
        ctx.put("username", JwtUtils.extractUserName(jwt));

        System.out.println("jwt " + jwt);

        DecodedJWT decodedJWT = JWT.decode(jwt);

        System.out.println(" iss " + decodedJWT.getIssuer());
        System.out.println(" sub " + decodedJWT.getSubject());
        System.out.println(" aud " + decodedJWT.getAudience());

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyContext = request.getRequestContext();
        APIGatewayProxyRequestEvent.RequestIdentity identity = proxyContext.getIdentity();

        String arn = String.format("arn:aws:execute-api:eu-west-1:%s:%s/%s/%s",
                proxyContext.getAccountId(),
                proxyContext.getApiId(),
//                proxyContext.getStage(),
//                proxyContext.getHttpMethod(),
                "*", "*");

        Statement statement = Statement.builder()
                .resource(arn)
                .effect("Allow")
                .build();

        PolicyDocument policyDocument = PolicyDocument.builder()
                .statements(
                        Collections.singletonList(statement)
                ).build();

        return AuthorizerResponse.builder()
                .principalId(identity.getAccountId())
                .policyDocument(policyDocument)
                .context(ctx)
                .build();
    }
}


