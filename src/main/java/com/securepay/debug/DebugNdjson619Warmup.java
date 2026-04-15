package com.securepay.debug;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class DebugNdjson619Warmup {

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        DebugNdjson619.appendReadyProbe();
    }
}
