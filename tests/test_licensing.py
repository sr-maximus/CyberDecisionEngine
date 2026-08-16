from __future__ import annotations

import asyncio

from cyberdeck_api.licensing import (
    CreateCompanyRequest,
    CreateLicenseRequest,
    CreateLicenseUserRequest,
    LicensingStore,
)


def test_licensing_store_seeds_plans_without_publishing_users(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    store = LicensingStore(tmp_path / "licensing.json")

    async def scenario():
        await store.load()
        overview = await store.overview()
        assert {plan.code for plan in overview.plans} == {"starter", "professional", "enterprise", "sovereign"}
        assert overview.users == []
        assert any(entry.action == "system.bootstrap" for entry in overview.audit_log)

        overview = await store.create_company(
            CreateCompanyRequest(name="Synthetic Organization", country="ZZ", sector="Test")
        )
        company = next(
            company for company in overview.companies if company.name == "Synthetic Organization"
        )

        overview = await store.create_license(
            CreateLicenseRequest(company_id=company.id, plan_code="starter", seats=3)
        )
        license_item = next(item for item in overview.licenses if item.company_id == company.id)
        assert license_item.effective_modules == ["overview", "dashboards", "brand", "attackSurface", "frameworks", "reports", "help"]

        overview = await store.create_user(
            CreateLicenseUserRequest(
                company_id=company.id,
                username="synthetic-operator",
                full_name="Synthetic Operator",
                role="admin",
                plan_code="starter",
                created_by="test-harness",
            )
        )
        user = next(item for item in overview.users if item.username == "synthetic-operator")
        assert user.plan_code == "starter"
        assert "settings" in user.effective_modules
        assert "brand" in user.effective_modules
        assert "socmint" not in user.effective_modules
        assert any(
            entry.action == "user.create" and entry.actor == "test-harness"
            for entry in overview.audit_log
        )

    asyncio.run(scenario())
