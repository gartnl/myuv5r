#ifndef APP_FLASHLIGHT_H
#define APP_FLASHLIGHT_H

#ifdef ENABLE_FLASHLIGHT

#include <stdint.h>

enum FlashlightMode_t {
    FLASHLIGHT_OFF = 0,
    FLASHLIGHT_ON,
    #ifndef ENABLE_NO_SOS    
        FLASHLIGHT_BLINK,
        FLASHLIGHT_SOS
    #endif
};

extern enum FlashlightMode_t gFlashLightState;
    #ifndef ENABLE_NO_SOS
    extern volatile uint16_t     gFlashLightBlinkCounter;
    void FlashlightTimeSlice(void);
    #endif
void ACTION_FlashLight(void);

#endif
#endif