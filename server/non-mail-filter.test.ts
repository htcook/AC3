import { describe, expect, it } from "vitest";
import { isNonMailAsset } from "./lib/email-security-analyzer";

describe("isNonMailAsset", () => {
  it("detects AWS EC2 hostnames as non-mail", () => {
    expect(isNonMailAsset("ec2-23-20-98-48.compute-1.amazonaws.com")).toBe(true);
    expect(isNonMailAsset("ec2-54-123-45-67.us-west-2.compute.amazonaws.com")).toBe(true);
  });

  it("detects GCP compute hostnames as non-mail", () => {
    expect(isNonMailAsset("my-instance.us-central1-a.compute.googleapis.com")).toBe(true);
  });

  it("detects Azure compute hostnames as non-mail", () => {
    expect(isNonMailAsset("myvm.westus.cloudapp.azure.com")).toBe(true);
    expect(isNonMailAsset("myapp.azurewebsites.net")).toBe(true);
  });

  it("detects CDN hostnames as non-mail", () => {
    expect(isNonMailAsset("d1234abcde.cloudfront.net")).toBe(true);
    expect(isNonMailAsset("example.cdn.cloudflare.net")).toBe(true);
    expect(isNonMailAsset("a1234.akamaiedge.net")).toBe(true);
    expect(isNonMailAsset("example.fastly.net")).toBe(true);
  });

  it("detects IP addresses as non-mail", () => {
    expect(isNonMailAsset("192.168.1.1")).toBe(true);
    expect(isNonMailAsset("10.0.0.1")).toBe(true);
    expect(isNonMailAsset("23.20.98.48")).toBe(true);
  });

  it("detects reverse-DNS PTR patterns as non-mail", () => {
    expect(isNonMailAsset("23-20-98-48.static.example.com")).toBe(true);
    expect(isNonMailAsset("1.2.3.4.in-addr.arpa")).toBe(true);
  });

  it("detects AWS ELB/EB/S3 hostnames as non-mail", () => {
    expect(isNonMailAsset("my-lb-1234.us-east-1.elb.amazonaws.com")).toBe(true);
    expect(isNonMailAsset("my-app.us-east-1.elasticbeanstalk.com")).toBe(true);
    expect(isNonMailAsset("mybucket.s3.amazonaws.com")).toBe(true);
    expect(isNonMailAsset("mybucket.s3-us-west-2.amazonaws.com")).toBe(true);
  });

  it("detects Heroku and DigitalOcean as non-mail", () => {
    expect(isNonMailAsset("myapp.herokuapp.com")).toBe(true);
    expect(isNonMailAsset("mybucket.digitaloceanspaces.com")).toBe(true);
  });

  it("does NOT flag regular domains as non-mail", () => {
    expect(isNonMailAsset("example.com")).toBe(false);
    expect(isNonMailAsset("mail.example.com")).toBe(false);
    expect(isNonMailAsset("sso.company.org")).toBe(false);
    expect(isNonMailAsset("api.myservice.io")).toBe(false);
    expect(isNonMailAsset("www.example.com")).toBe(false);
  });

  it("does NOT flag subdomains of regular domains as non-mail", () => {
    expect(isNonMailAsset("vpn.company.com")).toBe(false);
    expect(isNonMailAsset("admin.company.com")).toBe(false);
    expect(isNonMailAsset("portal.company.com")).toBe(false);
  });
});
