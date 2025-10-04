# Base syntax

To add a table, use three or more hyphens (---) to create each column’s header,
and use pipes (|) to separate each column. For compatibility, add a pipe on
either end of the row.
```md
| Lorem | Ipsum | Dolor | Sit | Amet |
| ----- | ----- | ----- | --- | ---- |
| Lorem | Ipsum | Dolor | Sit | Amet |
```

### Rendered Output

| Lorem | Ipsum | Dolor | Sit | Amet |
| ----- | ----- | ----- | --- | ---- |
| Lorem | Ipsum | Dolor | Sit | Amet |

### Syntax

```md
| Syntax    | Description |
| --------- | ----------- |
| Header    | Title       |
| Paragraph | Text        |
```

### Rendered Output

| Syntax    | Description |
| --------- | ----------- |
| Header    | Title       |
| Paragraph | Text        |

<!-- Alignment {{{ -->
## Alignment

The text can be aligned to the left, right, or center by adding a colon (:) to
the left, right, or on both side of the hyphens within the header row.

### Syntax

```md
| Syntax    | Description |   Test Text |
| :-------- | :---------: | ----------: |
| Header    |    Title    | Here's this |
| Paragraph |    Text     |    And more |
```

### Rendered Output

| Syntax    | Description |   Test Text |
| :-------- | :---------: | ----------: |
| Header    |    Title    | Here's this |
| Paragraph |    Text     |    And more |
<!-- }}} -->

## Escaping Pipe Characters in Tables

You can display a pipe (|) character in a table by using its HTML character code
(&#124;).

## Formatting text

Text within tables can be formatted:

- Links
- Code (`)
- Emphasis: **bold** or _italic_
