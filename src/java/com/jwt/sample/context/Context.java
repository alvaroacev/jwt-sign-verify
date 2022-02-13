package com.jwt.sample.context;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Setter
@Getter
@NoArgsConstructor
public class Context {
    private String ID = UUID.randomUUID().toString();

}
