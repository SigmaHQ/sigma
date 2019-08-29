# Breaking Changes in Sigma

Improvement sometimes makes it unavoidable to break with the past. This file describes the planned and implemented
breaking changes since 2019. Monitor this file if you use Sigma in productive environments.

Columns:

* Date: The date the change was or will be implemented. Planned dates may be subject of changes.
* Status may be one of:
    * Planned: there's the idea, but work hasn't begun.
    * Development: the change is currently developed.
    * Implemented: the development is finished, but the change was not yet merged to the master.
    * Merged: the change has been merged to the master branch. Breaking changes affecting only rules
      skip this state.
    * Released: the change has been released officially, this means:
        * Code or configuration of Sigma tools was pushed as [PyPI release](https://pypi.org/project/sigmatools/)
        * Sigma rules were merged to master.
* Issues: GitHub issues in the project repository for further details.
* Commit/Branch:
    * a development branch for the states *Development* and *Implemented*.
    * a commit reference to the merge commit for states from *Merged*.
* Release: [PyPI release](https://pypi.org/project/sigmatools/) that implements or will implement the change.
* Description: contains a short description of the change.

| Date       | Status   | Issues              | Commit/Branch   | Release | Description                                                                                                                                                 |
|------------|----------|---------------------|-----------------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2019-10-01 | Planned  | -                   | -               | -       | Field name cleanup                                                                                                                                          |
| 2019-08-01 | Released | -                   | config-cleanup  | 0.12    | Configuration name cleanup                                                                                                                                  |
| 2019-08-01 | Released | -                   | devel-modifiers | 0.12    | Pipe character must be escaped with backslash in field value names due to introduction of value modifiers                                                   |
| 2019-03-02 | Released | #136 #137 #139 #147 | 56a1ed1         | 0.9     | Introduction of [generic log sources](https://patzke.org/introducing-generic-log-sources-in-sigma.html) and *process_creation* as first generic log source. |
