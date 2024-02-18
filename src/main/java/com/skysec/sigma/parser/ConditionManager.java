package com.skysec.sigma.parser;

import cn.hutool.log.Log;
import cn.hutool.log.dialect.console.ConsoleLog;
import com.skysec.sigma.parser.model.Condition;

import java.util.ArrayList;
import java.util.List;

public class ConditionManager {

    private final Log console = new ConsoleLog(ConditionManager.class);

    private final List<Condition> conditions = new ArrayList<>();

    public void addCondition(Condition condition) {
        conditions.add(condition);
    }

    public List<Condition> getConditions() {
        return conditions;
    }

}
