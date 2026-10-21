/** The part of xml-encryption the tests use (it ships no types). */
declare module 'xml-encryption' {
  type Callback = (error: Error | null, result: string) => void;
  const xmlenc: {
    encrypt(content: string, options: Record<string, unknown>, callback: Callback): void;
    decrypt(xml: string, options: Record<string, unknown>, callback: Callback): void;
  };
  export default xmlenc;
}
