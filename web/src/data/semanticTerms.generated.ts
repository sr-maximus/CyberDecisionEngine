// Generated from config/term_registry.json. Run scripts/generate_semantic_terms.py.
export const semanticRegistryVersion = "1.0.0";
export const semanticTerms = {
  "collected_records": {
    "es": {
      "executive": "Registros recolectados",
      "technical": "Registros recolectados"
    },
    "en": {
      "executive": "Collected records",
      "technical": "Collected records"
    }
  },
  "security_event": {
    "es": {
      "executive": "Evento de seguridad",
      "technical": "Evento de seguridad"
    },
    "en": {
      "executive": "Security event",
      "technical": "Security event"
    }
  },
  "direct_evidence": {
    "es": {
      "executive": "Evidencia directa",
      "technical": "Evidencia directa"
    },
    "en": {
      "executive": "Direct evidence",
      "technical": "Direct evidence"
    }
  },
  "validated_finding": {
    "es": {
      "executive": "Hallazgo validado",
      "technical": "Hallazgo validado"
    },
    "en": {
      "executive": "Validated finding",
      "technical": "Validated finding"
    }
  },
  "confirmed": {
    "es": {
      "executive": "Confirmado",
      "technical": "Confirmado"
    },
    "en": {
      "executive": "Confirmed",
      "technical": "Confirmed"
    }
  },
  "alert": {
    "es": {
      "executive": "Alerta",
      "technical": "Alerta"
    },
    "en": {
      "executive": "Alert",
      "technical": "Alert"
    }
  },
  "risk": {
    "es": {
      "executive": "Riesgo",
      "technical": "Riesgo calculado"
    },
    "en": {
      "executive": "Calculated risk",
      "technical": "Calculated risk"
    }
  },
  "probability": {
    "es": {
      "executive": "Probabilidad calibrada",
      "technical": "Probabilidad calibrada"
    },
    "en": {
      "executive": "Calibrated probability",
      "technical": "Calibrated probability"
    }
  },
  "attack_observed": {
    "es": {
      "executive": "Comportamiento ATT&CK observado",
      "technical": "ATT&CK observado"
    },
    "en": {
      "executive": "Observed ATT&CK behavior",
      "technical": "Observed ATT&CK behavior"
    }
  },
  "confirmed_incident": {
    "es": {
      "executive": "Incidente confirmado",
      "technical": "Incidente confirmado"
    },
    "en": {
      "executive": "Confirmed incident",
      "technical": "Confirmed incident"
    }
  },
  "observed_zero": {
    "es": {
      "executive": "Cero observado",
      "technical": "Cero observado con cobertura suficiente"
    },
    "en": {
      "executive": "Observed zero",
      "technical": "Observed zero"
    }
  },
  "authorized_collection": {
    "es": {
      "executive": "Recolección autorizada",
      "technical": "Recolección autorizada"
    },
    "en": {
      "executive": "Authorized collection",
      "technical": "Authorized collection"
    }
  },
  "validated_evidence": {
    "es": {
      "executive": "Evidencia validada",
      "technical": "Evidencia validada"
    },
    "en": {
      "executive": "Validated evidence",
      "technical": "Validated evidence"
    }
  },
  "signal_concentration": {
    "es": {
      "executive": "Mayor concentración de señales",
      "technical": "Concentración de señales"
    },
    "en": {
      "executive": "Signal concentration",
      "technical": "Signal concentration"
    }
  },
  "external_exposure_intelligence_index": {
    "es": {
      "executive": "Índice de exposición e inteligencia externa",
      "technical": "Índice de exposición e inteligencia externa"
    },
    "en": {
      "executive": "External exposure and intelligence index",
      "technical": "External exposure and intelligence index"
    }
  },
  "signal_pressure_index": {
    "es": {
      "executive": "Índice de presión de señales",
      "technical": "Índice de presión de señales no calibrado"
    },
    "en": {
      "executive": "Signal pressure index",
      "technical": "Signal pressure index"
    }
  },
  "scenario_status": {
    "es": {
      "executive": "Estado de escenarios",
      "technical": "Estado de escenarios"
    },
    "en": {
      "executive": "Scenario status",
      "technical": "Scenario status"
    }
  },
  "control_mapping_coverage": {
    "es": {
      "executive": "Cobertura de mapeo de controles",
      "technical": "Cobertura de mapeo de controles"
    },
    "en": {
      "executive": "Control mapping coverage",
      "technical": "Control mapping coverage"
    }
  },
  "connector_operational_coverage": {
    "es": {
      "executive": "Cobertura operativa de conectores",
      "technical": "Cobertura operativa de conectores"
    },
    "en": {
      "executive": "Connector operational coverage",
      "technical": "Connector operational coverage"
    }
  },
  "no_validated_fraud_signals": {
    "es": {
      "executive": "Sin señales de fraude validadas en la cobertura disponible",
      "technical": "Sin señales de fraude validadas en la cobertura disponible"
    },
    "en": {
      "executive": "No validated fraud signals in available coverage",
      "technical": "No validated fraud signals in available coverage"
    }
  },
  "no_validated_reputational_impact": {
    "es": {
      "executive": "Sin impacto reputacional validado",
      "technical": "Sin impacto reputacional validado"
    },
    "en": {
      "executive": "No validated reputational impact",
      "technical": "No validated reputational impact"
    }
  }
} as const;

export type SemanticTermId = keyof typeof semanticTerms;
export function semanticLabel(
  termId: SemanticTermId,
  language: 'es' | 'en',
  audience: 'executive' | 'technical' = 'executive'
): string {
  return semanticTerms[termId][language][audience];
}
