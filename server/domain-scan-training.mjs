/**
 * Domain Intelligence Scan + CARVER Risk Card Generator
 * Processes domains through the auto-industry-carver module to generate
 * LLM training data and scoring logic tuning datasets.
 */

// Domain dataset organized by sector
const DOMAIN_DATASET = {
  banking_financial_services: {
    label: "Banking & Financial Services",
    regulatory: ["GLBA", "SOX", "FFIEC"],
    domains: [
      "jpmorganchase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com",
      "goldmansachs.com", "morganstanley.com", "capitalone.com", "usbank.com",
      "schwab.com", "americanexpress.com", "visa.com", "mastercard.com",
      "nasdaq.com", "cmegroup.com"
    ]
  },
  healthcare_providers: {
    label: "Healthcare & Life Sciences",
    regulatory: ["HIPAA", "HITECH"],
    domains: [
      "hcahealthcare.com", "mayo.edu", "clevelandclinic.org", "kaiserpermanente.org",
      "unitedhealthgroup.com", "cvshealth.com", "pfizer.com", "moderna.com",
      "johnsonandjohnson.com", "merck.com", "medtronic.com", "abbott.com"
    ]
  },
  defense_aerospace: {
    label: "Defense & Aerospace",
    regulatory: ["CMMC", "ITAR", "DFARS"],
    domains: [
      "lockheedmartin.com", "northropgrumman.com", "raytheon.com", "boeing.com",
      "generaldynamics.com", "bae-systems.com", "l3harris.com", "leidos.com", "saic.com"
    ]
  },
  federal_government: {
    label: "Government (Federal/State/Local)",
    regulatory: ["FISMA", "FedRAMP"],
    domains: [
      "whitehouse.gov", "treasury.gov", "defense.gov", "dhs.gov", "fbi.gov",
      "state.gov", "texas.gov", "ca.gov", "virginia.gov", "nyc.gov", "chicago.gov"
    ]
  },
  electric_gas_utilities: {
    label: "Energy & Utilities",
    regulatory: ["NERC_CIP"],
    domains: [
      "exeloncorp.com", "duke-energy.com", "southerncompany.com", "pgande.com",
      "coned.com", "nexteraenergy.com", "shell.com", "exxonmobil.com",
      "kindermorgan.com", "williams.com"
    ]
  },
  telecommunications: {
    label: "Telecommunications",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "att.com", "verizon.com", "tmobile.com", "comcast.com", "charter.com", "vodafone.com"
    ]
  },
  fintech: {
    label: "Payment Processors / FinTech",
    regulatory: ["GLBA"],
    sectorOverride: "banking_financial_services",
    domains: [
      "stripe.com", "squareup.com", "paypal.com", "adyen.com", "plaid.com"
    ]
  },
  education: {
    label: "Education",
    regulatory: [],
    sectorOverride: "federal_government",
    domains: [
      "harvard.edu", "mit.edu", "stanford.edu", "ucla.edu", "yale.edu", "k12.com"
    ]
  },
  chemical_manufacturing: {
    label: "Chemical & Industrial Manufacturing",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "dow.com", "dupont.com", "basf.com", "3m.com", "honeywell.com"
    ]
  },
  retail: {
    label: "Retail & E-Commerce",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "walmart.com", "target.com", "amazon.com", "bestbuy.com", "homedepot.com", "louisvuitton.com"
    ]
  },
  logistics: {
    label: "Logistics & Transportation",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "fedex.com", "ups.com", "dhl.com", "maersk.com", "delta.com", "united.com", "southwest.com"
    ]
  },
  hospitality: {
    label: "Hospitality",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "marriott.com", "hilton.com", "hyatt.com", "airbnb.com"
    ]
  },
  saas_tech: {
    label: "Technology / SaaS",
    regulatory: [],
    domains: [
      "microsoft.com", "google.com", "amazonaws.com", "salesforce.com", "oracle.com",
      "servicenow.com", "snowflake.com", "paloaltonetworks.com", "crowdstrike.com", "fortinet.com"
    ]
  },
  industrial_manufacturing: {
    label: "Industrial / Manufacturing",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "caterpillar.com", "john-deere.com", "siemens.com", "ge.com"
    ]
  },
  media: {
    label: "Media & Entertainment",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "netflix.com", "disney.com", "fox.com", "cnn.com", "nytimes.com"
    ]
  },
  construction: {
    label: "Construction & Infrastructure",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "bechtel.com", "kiewit.com", "jacobs.com"
    ]
  },
  agriculture: {
    label: "Agriculture & Food Production",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "cargill.com", "tysonfoods.com", "monsanto.com"
    ]
  },
  automotive: {
    label: "Automotive",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "ford.com", "gm.com", "tesla.com", "toyota.com"
    ]
  }
};

// Flatten all domains
const allEntries = [];
for (const [sectorKey, sectorData] of Object.entries(DOMAIN_DATASET)) {
  for (const domain of sectorData.domains) {
    allEntries.push({
      domain,
      sectorKey,
      sectorLabel: sectorData.label,
      regulatory: sectorData.regulatory,
      sectorOverride: sectorData.sectorOverride || null,
    });
  }
}

console.log(JSON.stringify(allEntries));
