type NoteProps = { note: { id: string; title: string; content: string; ownerId: string } };

export function Note({ note }: NoteProps) {
  return (
    <article>
      <h3>{note.title}</h3>
      <div dangerouslySetInnerHTML={{ __html: note.content }} />
    </article>
  );
}
