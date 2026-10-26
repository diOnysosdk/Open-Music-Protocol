# OMP contributor-role vocabulary v0.2

Vocabulary identifier: `omp-contributor-roles-v0.2`.

The initial closed tokens are:

`primary_artist`, `featured_artist`, `performer`, `vocalist`,
`instrumentalist`, `composer`, `lyricist`, `producer`, `engineer`, `mixer`,
and `mastering_engineer`.

Future vocabularies require a new identifier. Existing signed metadata retains
the vocabulary named in that object. Implementations must not silently map an
unknown role into a known role during validation or signing.
