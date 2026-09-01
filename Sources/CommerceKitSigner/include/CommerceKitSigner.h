#pragma once

#include <stddef.h>

int APCommerceKitSign(
    const unsigned char *input,
    size_t inputLength,
    unsigned char **output,
    size_t *outputLength,
    char **errorMessage
);
