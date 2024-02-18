package com.skysec.sigma.parser.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * sigma detections 集合
 */
public class SigmaDetection {

    @Setter
    @Getter
    private List<Detection> detections = new ArrayList<>();

    public void addDetection(Detection detection) {
        detections.add(detection);
    }

}
