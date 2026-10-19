package com.uc.ms_security.dto.permission;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public abstract class BasePermissionDTO {

    @NotBlank(
            message = "La url es obligatoria"
    )
    @Size(
            max = 255,
            message = "La url no debe superar los 255 caracteres"
    )
    private String url;

    @NotBlank(
            message = "El método HTTP es obligatorio"
    )
    @Size(
            max = 10,
            message = "El método HTTP no debe superar los 10 caracteres"
    )
    private String method;

    @Size(
            max = 100,
            message = "El modelo no debe superar los 100 caracteres"
    )
    private String model;
}