# Blockquotes

To create a blockquote, add a > in front of a paragraph.

```md
> This is a blockquote
```

### Rendered output

> This is a blockquote

## Blockquotes with multiple paragraphs

Blockquotes can contain multiple paragraphs. Add a `>` on the blank lines
between the paragraphs.
```md
> This is a paragraph.
>
> This is a new paragraph.
```

### Rendered output

> This is a paragraph.
>
> This is a new paragraph.

## Nested blockquotes

Blockquotes can be nested. Add a `>>` in front of the paragraph you want to
nest.
```md
> This is a blockquote.
>
>> This is a nested blockquote.
```

> This is a blockquote.
>
>> This is a nested blockquote.

## Blockquotes with other elements

Blockquotes can contain other Markdown formatted elements. Note that not all
elements are supported.
```md
> #### Header level 4
>
> - This is the first unordered list item.
> - This is the second unordered list item.
>
>  This text is _italic_ and **bold**.
```

### Rendered output

> #### Header level 4
>
> - This is the first unordered list item.
> - This is the second unordered list item.
>
>  This text is _italic_ and **bold**.
