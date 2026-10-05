import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

/** Approved repository Markdown; HTML is disabled and URL safety is kept default. */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="x:space-y-5 x:leading-7 x:[&_a]:underline x:[&_h2]:mt-8 x:[&_h2]:text-xl x:[&_h2]:font-semibold x:[&_h3]:mt-6 x:[&_h3]:text-lg x:[&_h3]:font-semibold x:[&_ul]:list-disc x:[&_ul]:pl-6 x:[&_ol]:list-decimal x:[&_ol]:pl-6 x:[&_blockquote]:border-l-4 x:[&_blockquote]:pl-4 x:[&_pre]:overflow-x-auto x:[&_pre]:rounded x:[&_pre]:bg-gray-100 x:dark:[&_pre]:bg-gray-900 x:[&_pre]:p-4 x:[&_table]:block x:[&_table]:overflow-x-auto x:[&_th]:border x:[&_th]:px-3 x:[&_td]:border x:[&_td]:px-3">
      <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml>{children}</ReactMarkdown>
    </div>
  );
}
