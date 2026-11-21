import { describe, expect, it } from "vitest";
import { qs } from "./api";
import { HOURS_LABEL, ago, pct, safeUrl, versionText } from "./format";

describe("format helpers", () => {
  it("only allows http(s) links", () => {
    expect(safeUrl("https://osv.dev/vulnerability/GHSA-1")).toBe("https://osv.dev/vulnerability/GHSA-1");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("data:text/html,x")).toBeNull();
    expect(safeUrl("not a url")).toBeNull();
  });

  it("never presents an unknown version as a real one", () => {
    expect(versionText("1.2.3", "exact")).toBe("1.2.3");
    expect(versionText(null, "unknown")).toBe("unknown");
    expect(versionText(null, "constraint", "^4.0")).toBe("^4.0 (constraint)");
  });

  it("formats relative times", () => {
    const now = Date.parse("2026-01-02T00:00:00Z");
    expect(ago(null, now)).toBe("never");
    expect(ago("2026-01-01T23:30:00Z", now)).toBe("30 min ago");
    expect(ago("2025-12-30T00:00:00Z", now)).toBe("3 d ago");
  });

  it("builds query strings without empty values", () => {
    expect(qs({ a: 1, b: "", c: ["x", "y"], d: undefined })).toBe("?a=1&c=x&c=y");
  });

  it("formats EPSS and schedules", () => {
    expect(pct(null)).toBe("-");
    expect(pct(0.0004)).toBe("<0.1%");
    expect(pct(0.0523)).toBe("5.2%");
    expect(pct(0.97)).toBe("97%");
    expect(pct(0.9996)).toBe(">99%");
    expect(HOURS_LABEL(0)).toBe("Manual only");
    expect(HOURS_LABEL(24)).toBe("Daily");
    expect(HOURS_LABEL(72)).toBe("Every 3 days");
  });
});
