# Placeholder Rules

These are rules that are flexible detection templates that can be customized for your environments or use cases. Examples include rules that would require a domain or workstation variation that is specific to the company environment. This would vary on a case by basis

As a result, placeholder rules serve as an abstract detection template, where you adjust the plaecholder value to fit your use case.

### Placeholder Transformations
Placeholders can be mapped to the following 

- value_placeholders
- query_expression_placeholders
- wildcard_placeholders

As stated in the included [documentation](https://blog.sigmahq.io/building-flexible-detections-with-sigma-placeholders-7c1b814e2860?gi=5deebe790b12), this is to keep private rules clean and make any environment-specific information reusable to the community.
You use one of the placeholder transformations above, and future users of the rule can simply adjust the value to their use case. 

### Reference

[Sigma Blog Post](https://blog.sigmahq.io/building-flexible-detections-with-sigma-placeholders-7c1b814e2860?gi=5deebe790b12)