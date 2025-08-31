package com.mlvu.mlvu_auth.payload.request;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

@Data
public class ClerkWebhookRequest {
    private String type;
    private JsonNode data;
}