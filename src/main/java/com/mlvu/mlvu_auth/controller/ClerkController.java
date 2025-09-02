package com.mlvu.mlvu_auth.controller;

import com.mlvu.mlvu_auth.payload.request.ClerkWebhookRequest;
import com.mlvu.mlvu_auth.service.ClerkService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
@RestController
@RequestMapping("/api/clerk")
public class ClerkController {

    @Autowired
    private ClerkService clerkService;

    @PostMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestParam String token) {
        return clerkService.validateClerkToken(token);
    }

    @PostMapping("/webhook")
    public ResponseEntity<?> handleWebhook(@RequestBody ClerkWebhookRequest webhookRequest) {
        return clerkService.handleWebhook(webhookRequest);
    }
}