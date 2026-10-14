import { useEffect, useRef, useState } from 'react';
import { Annotation, Compartment, EditorState, Transaction } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import {
  autocompletion,
  closeBrackets,
  closeBracketsKeymap,
  closeCompletion,
} from '@codemirror/autocomplete';
import {
  bracketMatching,
  HighlightStyle,
  indentOnInput,
  syntaxHighlighting,
} from '@codemirror/language';
import { closeSearchPanel, search, searchKeymap } from '@codemirror/search';
import { PostgreSQL, sql, type SQLNamespace } from '@codemirror/lang-sql';
import { tags } from '@lezer/highlight';
import { executeQuery } from '../labApi';
import './code-editor.css';

type Props = {
  value: string;
  onChange: (value: string) => void;
  label: string;
  language: 'sql';
  className?: string;
  readOnly?: boolean;
  autoFocus?: boolean;
  onRun?: (cursor: number) => void;
  onEscape?: () => void;
  onBlur?: () => void;
};

const externalChange = Annotation.define<boolean>();
const colors = HighlightStyle.define([
  { tag: tags.keyword, color: '#c5a8ff' },
  { tag: [tags.string, tags.special(tags.string)], color: '#80dfaf' },
  { tag: [tags.number, tags.bool, tags.null], color: '#f4ba80' },
  { tag: tags.comment, color: '#a5b3ba', fontStyle: 'italic' },
  { tag: tags.heading, color: '#51dccb', fontWeight: 'bold' },
  { tag: tags.link, color: '#8fcaff', textDecoration: 'underline' },
  { tag: tags.strong, fontWeight: 'bold' },
  { tag: tags.emphasis, fontStyle: 'italic' },
]);

// Share only metadata between editors. Failed requests are not cached, and a
// focus after 30 seconds refreshes suggestions without executing draft SQL.
let catalogue: { schema: SQLNamespace; expires: number } | undefined;
let pendingCatalogue: Promise<SQLNamespace> | undefined;
function completionSchema(): Promise<SQLNamespace> {
  if (catalogue && Date.now() < catalogue.expires) return Promise.resolve(catalogue.schema);
  return (pendingCatalogue ??= executeQuery('', '/api/catalogue')
    .promise.then((result) => {
      const schema: Record<
        string,
        Record<string, { label: string; type: string; detail: string }[]>
      > = Object.create(null);
      for (const [namespace, table, , , column, type] of result.rows) {
        if (
          typeof namespace !== 'string' ||
          typeof table !== 'string' ||
          typeof column !== 'string'
        )
          continue;
        const tables = (schema[namespace] ??= Object.create(null));
        (tables[table] ??= []).push({
          label: column,
          type: 'property',
          detail: String(type ?? ''),
        });
      }
      catalogue = { schema, expires: Date.now() + 30_000 };
      return schema;
    })
    .finally(() => {
      pendingCatalogue = undefined;
    }));
}

export function CodeEditor(props: Props) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const latest = useRef(props);
  latest.current = props;
  const [configuration] = useState(() => new Compartment());
  const [schema, setSchema] = useState<SQLNamespace>({});

  useEffect(() => {
    let disposed = false;
    const refresh = () => {
      void completionSchema()
        .then((value) => {
          if (!disposed) setSchema(value);
        })
        .catch(() => {
          if (!disposed) setSchema({});
        });
    };
    const editor = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: latest.current.value,
        extensions: [
          configuration.of([]),
          lineNumbers(),
          history(),
          highlightActiveLine(),
          EditorView.lineWrapping,
          indentOnInput(),
          bracketMatching(),
          closeBrackets(),
          syntaxHighlighting(colors),
          autocompletion(),
          search({ top: true }),
          keymap.of([
            {
              key: 'Mod-Enter',
              run: (current) => {
                if (!latest.current.onRun) return false;
                closeCompletion(current);
                latest.current.onRun(current.state.selection.main.from);
                return true;
              },
            },
            {
              key: 'Escape',
              run: (current) => {
                if (closeCompletion(current) || closeSearchPanel(current)) return true;
                if (!latest.current.onEscape) return false;
                latest.current.onEscape();
                return true;
              },
            },
            ...closeBracketsKeymap,
            // Workspace shortcuts keep their existing meaning.
            ...defaultKeymap.filter((binding) => !['Mod-d', 'Ctrl-t'].includes(binding.key ?? '')),
            ...historyKeymap,
            ...searchKeymap,
          ]),
          EditorView.updateListener.of((update) => {
            if (
              update.docChanged &&
              !update.transactions.some((tr) => tr.annotation(externalChange))
            ) {
              latest.current.onChange(update.state.doc.toString());
            }
          }),
          EditorView.domEventHandlers({
            focus: () => {
              refresh();
            },
          }),
        ],
      }),
    });
    view.current = editor;
    refresh();
    if (latest.current.autoFocus) editor.focus();
    return () => {
      disposed = true;
      view.current = null;
      editor.destroy();
    };
  }, [configuration]);

  useEffect(() => {
    const sqlSupport = sql({
      dialect: PostgreSQL,
      schema,
      defaultSchema: 'evidence',
      upperCaseKeywords: true,
    });
    view.current?.dispatch({
      effects: configuration.reconfigure([
        sqlSupport,
        EditorState.readOnly.of(!!props.readOnly),
        EditorView.contentAttributes.of({
          'aria-label': props.label,
          'aria-readonly': String(!!props.readOnly),
          'aria-multiline': 'true',
          spellcheck: 'false',
        }),
      ]),
    });
  }, [configuration, props.language, props.label, props.readOnly, schema]);

  useEffect(() => {
    const editor = view.current;
    if (editor && editor.state.doc.toString() !== props.value) {
      editor.dispatch({
        changes: { from: 0, to: editor.state.doc.length, insert: props.value },
        annotations: [externalChange.of(true), Transaction.addToHistory.of(false)],
      });
    }
  }, [props.value]);

  return (
    <div
      ref={host}
      className={`code-editor ${props.className ?? ''}`}
      onBlur={() => {
        // Include focus leaving search-panel controls, not just the document.
        requestAnimationFrame(() => {
          if (view.current && !host.current?.contains(document.activeElement))
            latest.current.onBlur?.();
        });
      }}
    />
  );
}
