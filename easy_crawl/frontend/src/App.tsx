import { useState } from 'react';
import { Search, Globe, FileText, Loader2, Code, FileJson, FileType, AlignLeft, ChevronDown, ChevronUp, X, Copy, Check, Zap } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

// Types
type OutputFormat = 'markdown' | 'json' | 'text';
type Menu = 'scrape' | 'search' | 'crawl';

interface SearchResult {
  title: string;
  url: string;
  snippet: string;
  displayed_url: string;
}

interface GoogleSearchResponse {
  template: string;
  version: string;
  data: {
    query: string;
    results: SearchResult[];
    next_page: string;
  };
}

const API_URL = 'http://localhost:8000';

// Decode common HTML entities
const decodeHtmlEntities = (text: string): string => {
  const entities: Record<string, string> = {
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&nbsp;': ' ',
    '&#x27;': "'",
    '&#x2F;': '/',
  };
  return text.replace(/&[#\w]+;/g, (match) => entities[match] || match);
};

function App() {
  const [activeMenu, setActiveMenu] = useState<Menu>('scrape');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Scrape State
  const [scrapeUrl, setScrapeUrl] = useState('');
  const [scrapeFormat, setScrapeFormat] = useState<OutputFormat>('markdown');
  const [scrapeResult, setScrapeResult] = useState<any>(null);

  // Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [searchResponseQuery, setSearchResponseQuery] = useState('');
  const [searchNextPage, setSearchNextPage] = useState('');

  // Crawl State
  const [crawlUrl, setCrawlUrl] = useState('');
  const [crawlDepth, setCrawlDepth] = useState(2);
  const [crawlMaxPages, setCrawlMaxPages] = useState(5);
  const [crawlFollowExternal, setCrawlFollowExternal] = useState(false);
  const [crawlFormat, setCrawlFormat] = useState<OutputFormat>('markdown');
  const [crawlIncludeImages, setCrawlIncludeImages] = useState(true);
  const [crawlIncludeMetadata, setCrawlIncludeMetadata] = useState(true);
  const [crawlExcludePatterns, setCrawlExcludePatterns] = useState('');
  const [crawlTimeout, setCrawlTimeout] = useState(10000);
  const [showAdvancedCrawl, setShowAdvancedCrawl] = useState(false);
  
  const [crawlJobId, setCrawlJobId] = useState<string | null>(null);
  const [crawlProgress, setCrawlProgress] = useState<any>(null);
  const [crawlResult, setCrawlResult] = useState<any>(null);

  // Code Modal State
  const [showCodeModal, setShowCodeModal] = useState(false);
  const [curlCode, setCurlCode] = useState('');
  const [copied, setCopied] = useState(false);

  // Copy result state
  const [copiedResult, setCopiedResult] = useState<string | null>(null);

  // Timing state
  const [scrapeDuration, setScrapeDuration] = useState<number | null>(null);
  const [searchDuration, setSearchDuration] = useState<number | null>(null);
  const [crawlStartTime, setCrawlStartTime] = useState<number | null>(null);
  const [crawlDuration, setCrawlDuration] = useState<number | null>(null);

  // Actions
  const handleScrape = async () => {
    if (!scrapeUrl) return;
    setLoading(true);
    setError(null);
    setScrapeResult(null);
    setScrapeDuration(null);
    const startTime = performance.now();
    try {
      const res = await fetch(`${API_URL}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: `https://${scrapeUrl}`, output_format: scrapeFormat }),
      });
      const data = await res.json();
      const endTime = performance.now();
      setScrapeDuration(endTime - startTime);
      setScrapeResult(data);
    } catch (err) {
      setError('Failed to scrape URL');
      console.error(err);
    }
    setLoading(false);
  };

  const handleSearch = async () => {
    if (!searchQuery) return;
    setLoading(true);
    setError(null);
    setSearchResults([]);
    setSearchResponseQuery('');
    setSearchNextPage('');
    setSearchDuration(null);
    const startTime = performance.now();
    try {
      const res = await fetch(`${API_URL}/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: searchQuery }),
      });
      const data = await res.json();
      const endTime = performance.now();
      setSearchDuration(endTime - startTime);

      // Handle Google search template response structure
      // Structure: { results: { template, version, data: { query, results: [...], next_page } } }
      let searchData: GoogleSearchResponse | null = null;

      if (data.results) {
        if (typeof data.results === 'string') {
          try {
            searchData = JSON.parse(data.results);
          } catch (e) {
            console.error('Failed to parse results string:', e);
          }
        } else if (data.results.template === 'google_search') {
          searchData = data.results;
        } else if (data.results.data?.results) {
          // Nested structure
          searchData = data.results;
        }
      }

      if (searchData?.data?.results) {
        setSearchResults(searchData.data.results);
        setSearchResponseQuery(searchData.data.query || '');
        setSearchNextPage(searchData.data.next_page || '');
      } else if (Array.isArray(data.results)) {
        // Fallback for simple array
        setSearchResults(data.results);
      }
    } catch (err) {
      setError('Failed to search');
      console.error(err);
    }
    setLoading(false);
  };

  const handleCrawlStart = async () => {
    if (!crawlUrl) return;
    setLoading(true);
    setError(null);
    setCrawlJobId(null);
    setCrawlProgress(null);
    setCrawlResult(null);
    setCrawlDuration(null);
    setCrawlStartTime(performance.now());

    const excludeList = crawlExcludePatterns.split(',').map(s => s.trim()).filter(Boolean);

    try {
      const res = await fetch(`${API_URL}/crawl/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          url: `https://${crawlUrl}`, 
          depth: crawlDepth, 
          max_pages: crawlMaxPages,
          follow_external: crawlFollowExternal,
          output_format: crawlFormat,
          include_images: crawlIncludeImages,
          include_metadata: crawlIncludeMetadata,
          exclude_patterns: excludeList.length > 0 ? excludeList : null,
          timeout_per_page: crawlTimeout
        }),
      });
      const data = await res.json();
      if (data.job_id) {
        setCrawlJobId(data.job_id);
        pollProgress(data.job_id);
      }
    } catch (err) {
      setError('Failed to start crawl');
      console.error(err);
    }
    setLoading(false);
  };

  const pollProgress = async (jobId: string) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/crawl/${jobId}/progress`);
        const data = await res.json();
        setCrawlProgress(data);

        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(interval);
          if (data.status === 'completed') {
            fetchCrawlResult(jobId);
          }
        }
      } catch (err) {
        clearInterval(interval);
      }
    }, 2000);
  };

  const fetchCrawlResult = async (jobId: string) => {
    try {
      const res = await fetch(`${API_URL}/crawl/${jobId}/result`);
      const data = await res.json();
      setCrawlResult(data);
      if (crawlStartTime) {
        setCrawlDuration(performance.now() - crawlStartTime);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const generateCurl = () => {
    let endpoint = '';
    let body = {};

    if (activeMenu === 'scrape') {
      endpoint = '/scrape';
      body = { url: `https://${scrapeUrl || 'example.com'}`, output_format: scrapeFormat };
    } else if (activeMenu === 'search') {
      endpoint = '/search';
      body = { query: searchQuery || 'search query' };
    } else if (activeMenu === 'crawl') {
      endpoint = '/crawl/start';
      const excludeList = crawlExcludePatterns.split(',').map(s => s.trim()).filter(Boolean);
      body = {
        url: `https://${crawlUrl || 'example.com'}`,
        depth: crawlDepth,
        max_pages: crawlMaxPages,
        follow_external: crawlFollowExternal,
        output_format: crawlFormat,
        include_images: crawlIncludeImages,
        include_metadata: crawlIncludeMetadata,
        exclude_patterns: excludeList.length > 0 ? excludeList : null,
        timeout_per_page: crawlTimeout
      };
    }

    const command = `curl -X POST "${API_URL}${endpoint}" \
  -H "Content-Type: application/json" \
  -d '${JSON.stringify(body, null, 2)}'`;
    
    setCurlCode(command);
    setShowCodeModal(true);
    setCopied(false);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(curlCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const copyResultToClipboard = (content: string, id: string) => {
    navigator.clipboard.writeText(content);
    setCopiedResult(id);
    setTimeout(() => setCopiedResult(null), 2000);
  };

  const formatDuration = (ms: number): string => {
    if (ms < 1000) {
      return `${Math.round(ms)}ms`;
    } else if (ms < 60000) {
      return `${(ms / 1000).toFixed(2)}s`;
    } else {
      const minutes = Math.floor(ms / 60000);
      const seconds = ((ms % 60000) / 1000).toFixed(1);
      return `${minutes}m ${seconds}s`;
    }
  };

  return (
    <div className="min-h-screen bg-[#F9FAFB] flex flex-col items-center py-20 px-4 font-sans text-gray-800 relative">
      
      {/* Header */}
      <div className="text-center mb-12">
        <h1 className="text-5xl font-bold mb-4 tracking-tight">Easy Crawl</h1>
        <p className="text-gray-500 text-lg">
          API, Docs and Playground - all in one place
        </p>
      </div>

      {/* Navigation Tabs */}
      <div className="bg-gray-100 p-1.5 rounded-xl flex items-center gap-1 mb-8 shadow-inner">
        <button
          onClick={() => setActiveMenu('scrape')}
          className={`px-6 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-all ${activeMenu === 'scrape' ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}
        >
          <FileText className="w-4 h-4" />
          Scrape
        </button>
        <button
          onClick={() => setActiveMenu('search')}
          className={`px-6 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-all ${activeMenu === 'search' ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}
        >
          <Search className="w-4 h-4" />
          Search
        </button>
        <button
          onClick={() => setActiveMenu('crawl')}
          className={`px-6 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-all ${activeMenu === 'crawl' ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}
        >
          <Globe className="w-4 h-4" />
          Crawl
        </button>
      </div>

      {/* Main Card */}
      <div className="w-full max-w-3xl bg-white rounded-2xl shadow-xl border border-gray-100 overflow-hidden">
        <div className="p-2">
          
          {/* Scrape Input */}
          {activeMenu === 'scrape' && (
            <div className="flex flex-col">
              <div className="flex items-center px-4 py-3 border-b border-gray-100">
                 <span className="text-gray-400 font-medium mr-2 select-none">https://</span>
                 <input
                    type="text"
                    placeholder="example.com"
                    value={scrapeUrl}
                    onChange={(e) => setScrapeUrl(e.target.value.replace('https://', '').replace('http://', ''))}
                    className="flex-1 text-lg outline-none text-gray-800 placeholder-gray-300"
                 />
              </div>
              <div className="p-4 flex items-center justify-between bg-gray-50/50">
                <div className="flex items-center gap-2">
                  <button 
                    onClick={() => setScrapeFormat('markdown')}
                    className={`p-2 rounded-lg border transition-all ${scrapeFormat === 'markdown' ? 'bg-primary/10 border-primary text-primary' : 'bg-white border-gray-200 text-gray-500 hover:border-gray-300'}`}
                    title="Markdown"
                  >
                    <FileType className="w-4 h-4" />
                  </button>
                  <button 
                    onClick={() => setScrapeFormat('json')}
                    className={`p-2 rounded-lg border transition-all ${scrapeFormat === 'json' ? 'bg-primary/10 border-primary text-primary' : 'bg-white border-gray-200 text-gray-500 hover:border-gray-300'}`}
                    title="JSON"
                  >
                    <FileJson className="w-4 h-4" />
                  </button>
                  <button 
                    onClick={() => setScrapeFormat('text')}
                    className={`p-2 rounded-lg border transition-all ${scrapeFormat === 'text' ? 'bg-primary/10 border-primary text-primary' : 'bg-white border-gray-200 text-gray-500 hover:border-gray-300'}`}
                    title="Text"
                  >
                    <AlignLeft className="w-4 h-4" />
                  </button>
                </div>
                <div className="flex gap-3">
                  <button 
                    onClick={generateCurl}
                    className="px-4 py-2 text-gray-600 font-medium hover:bg-gray-100 rounded-lg transition-colors flex items-center gap-2"
                  >
                    <Code className="w-4 h-4" />
                    Get code
                  </button>
                  <button
                    onClick={handleScrape}
                    disabled={loading || !scrapeUrl}
                    className="bg-primary hover:bg-emerald-600 text-white px-6 py-2 rounded-lg font-medium transition-all shadow-lg shadow-primary/30 disabled:opacity-50 disabled:shadow-none flex items-center gap-2"
                  >
                    {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Start scraping"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Search Input */}
          {activeMenu === 'search' && (
             <div className="flex flex-col">
               <div className="flex items-center px-4 py-3 border-b border-gray-100">
                  <Search className="w-5 h-5 text-gray-400 mr-3" />
                  <input
                     type="text"
                     placeholder="Search query..."
                     value={searchQuery}
                     onChange={(e) => setSearchQuery(e.target.value)}
                     className="flex-1 text-lg outline-none text-gray-800 placeholder-gray-300"
                     onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  />
               </div>
               <div className="p-4 flex justify-end gap-3 bg-gray-50/50">
                   <button 
                     onClick={generateCurl}
                     className="px-4 py-2 text-gray-600 font-medium hover:bg-gray-100 rounded-lg transition-colors flex items-center gap-2"
                   >
                     <Code className="w-4 h-4" />
                     Get code
                   </button>
                   <button
                     onClick={handleSearch}
                     disabled={loading || !searchQuery}
                     className="bg-primary hover:bg-emerald-600 text-white px-6 py-2 rounded-lg font-medium transition-all shadow-lg shadow-primary/30 disabled:opacity-50 disabled:shadow-none flex items-center gap-2"
                   >
                     {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Search Google"}
                   </button>
               </div>
             </div>
          )}

          {/* Crawl Input */}
          {activeMenu === 'crawl' && (
             <div className="flex flex-col">
               <div className="flex items-center px-4 py-3 border-b border-gray-100">
                  <span className="text-gray-400 font-medium mr-2 select-none">https://</span>
                  <input
                     type="text"
                     placeholder="example.com"
                     value={crawlUrl}
                     onChange={(e) => setCrawlUrl(e.target.value.replace('https://', '').replace('http://', ''))}
                     className="flex-1 text-lg outline-none text-gray-800 placeholder-gray-300"
                  />
               </div>
               
               {/* Basic Settings */}
               <div className="px-6 py-4 bg-gray-50/30 border-b border-gray-100">
                   <div className="flex items-center gap-6">
                       <div className="flex items-center gap-2">
                          <label className="text-sm font-medium text-gray-600">Depth</label>
                          <input 
                            type="number" 
                            value={crawlDepth} 
                            onChange={e => setCrawlDepth(Number(e.target.value))}
                            className="w-16 px-2 py-1.5 border border-gray-200 rounded-lg text-center bg-white outline-none focus:border-primary focus:ring-1 focus:ring-primary/50 transition-all text-sm"
                          />
                       </div>
                       <div className="flex items-center gap-2">
                          <label className="text-sm font-medium text-gray-600">Max Pages</label>
                          <input 
                            type="number" 
                            value={crawlMaxPages} 
                            onChange={e => setCrawlMaxPages(Number(e.target.value))}
                            className="w-16 px-2 py-1.5 border border-gray-200 rounded-lg text-center bg-white outline-none focus:border-primary focus:ring-1 focus:ring-primary/50 transition-all text-sm"
                          />
                       </div>
                   </div>
               </div>

               {/* Advanced Settings Toggle */}
               <div className="px-6 py-2 bg-gray-50/50 border-b border-gray-100">
                  <button 
                    onClick={() => setShowAdvancedCrawl(!showAdvancedCrawl)}
                    className="flex items-center gap-2 text-sm text-gray-500 hover:text-primary transition-colors py-1"
                  >
                    {showAdvancedCrawl ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    Advanced Settings
                  </button>
               </div>

               {/* Advanced Settings Panel */}
               {showAdvancedCrawl && (
                  <div className="px-6 py-4 bg-gray-50 border-b border-gray-100 grid grid-cols-2 gap-x-8 gap-y-4 animate-fadeIn text-sm">
                      <div className="flex items-center justify-between">
                          <label className="text-gray-600">Output Format</label>
                          <select 
                            value={crawlFormat}
                            onChange={(e) => setCrawlFormat(e.target.value as OutputFormat)}
                            className="px-2 py-1.5 border border-gray-200 rounded-lg bg-white outline-none focus:border-primary w-32"
                          >
                             <option value="markdown">Markdown</option>
                             <option value="json">JSON</option>
                             <option value="text">Text</option>
                          </select>
                      </div>
                      
                      <div className="flex items-center justify-between">
                          <label className="text-gray-600">Timeout (ms)</label>
                          <input 
                            type="number" 
                            value={crawlTimeout} 
                            onChange={e => setCrawlTimeout(Number(e.target.value))}
                            className="w-32 px-2 py-1.5 border border-gray-200 rounded-lg bg-white outline-none focus:border-primary"
                          />
                      </div>

                      <div className="flex items-center gap-2">
                          <input 
                            type="checkbox" 
                            id="followExternal"
                            checked={crawlFollowExternal}
                            onChange={e => setCrawlFollowExternal(e.target.checked)}
                            className="rounded border-gray-300 text-primary focus:ring-primary"
                          />
                          <label htmlFor="followExternal" className="text-gray-600 select-none">Follow External Links</label>
                      </div>

                      <div className="flex items-center gap-2">
                          <input 
                            type="checkbox" 
                            id="includeImages"
                            checked={crawlIncludeImages}
                            onChange={e => setCrawlIncludeImages(e.target.checked)}
                            className="rounded border-gray-300 text-primary focus:ring-primary"
                          />
                          <label htmlFor="includeImages" className="text-gray-600 select-none">Include Images</label>
                      </div>

                      <div className="flex items-center gap-2">
                          <input 
                            type="checkbox" 
                            id="includeMetadata"
                            checked={crawlIncludeMetadata}
                            onChange={e => setCrawlIncludeMetadata(e.target.checked)}
                            className="rounded border-gray-300 text-primary focus:ring-primary"
                          />
                          <label htmlFor="includeMetadata" className="text-gray-600 select-none">Include Metadata</label>
                      </div>
                      
                      <div className="col-span-2">
                          <label className="block text-gray-600 mb-1">Exclude Patterns (comma separated)</label>
                          <input 
                            type="text" 
                            value={crawlExcludePatterns}
                            onChange={e => setCrawlExcludePatterns(e.target.value)}
                            placeholder="e.g. /login, /admin, .pdf"
                            className="w-full px-3 py-1.5 border border-gray-200 rounded-lg bg-white outline-none focus:border-primary"
                          />
                      </div>
                  </div>
               )}

               <div className="p-4 flex justify-end gap-3 bg-gray-50/50">
                   <button 
                     onClick={generateCurl}
                     className="px-4 py-2 text-gray-600 font-medium hover:bg-gray-100 rounded-lg transition-colors flex items-center gap-2"
                   >
                     <Code className="w-4 h-4" />
                     Get code
                   </button>
                   <button
                     onClick={handleCrawlStart}
                     disabled={loading || !crawlUrl}
                     className="bg-primary hover:bg-emerald-600 text-white px-6 py-2 rounded-lg font-medium transition-all shadow-lg shadow-primary/30 disabled:opacity-50 disabled:shadow-none flex items-center gap-2"
                   >
                     {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : "Start Crawl"}
                   </button>
               </div>
             </div>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mt-6 p-4 bg-red-50 text-red-700 rounded-lg border border-red-200 w-full max-w-3xl animate-fadeIn">
          {error}
        </div>
      )}

      {/* Results Section */}
      <div className="w-full max-w-3xl mt-8 space-y-6">
        
        {/* Scrape Result */}
        {activeMenu === 'scrape' && scrapeResult && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden animate-fadeIn">
            <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50/50">
              <div className="flex items-center gap-3">
                <h3 className="font-semibold text-gray-700">Result</h3>
                {scrapeDuration && (
                  <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium">
                    <Zap className="w-3 h-3" />
                    {formatDuration(scrapeDuration)}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-gray-500 uppercase">{scrapeFormat}</span>
                <button
                  onClick={() => copyResultToClipboard(
                    typeof scrapeResult.content === 'object'
                      ? JSON.stringify(scrapeResult.content, null, 2)
                      : scrapeResult.content,
                    'scrape'
                  )}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  {copiedResult === 'scrape' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                  {copiedResult === 'scrape' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>
            <div className="p-6 overflow-x-auto max-h-[600px] overflow-y-auto">
              {scrapeFormat === 'markdown' ? (
                <article className="prose prose-emerald prose-sm max-w-none">
                  <ReactMarkdown>{scrapeResult.content}</ReactMarkdown>
                </article>
              ) : scrapeFormat === 'json' ? (
                <pre className="text-xs font-mono text-gray-600 whitespace-pre-wrap bg-gray-50 p-4 rounded-lg">
                   {typeof scrapeResult.content === 'object'
                      ? JSON.stringify(scrapeResult.content, null, 2)
                      : scrapeResult.content}
                </pre>
              ) : (
                <pre className="text-sm font-mono text-gray-700 whitespace-pre-wrap leading-relaxed">
                   {scrapeResult.content}
                </pre>
              )}
            </div>
          </div>
        )}

        {/* Search Results */}
        {activeMenu === 'search' && searchResults.length > 0 && (
          <div className="space-y-4 animate-fadeIn">
            {/* Search header with stats */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3 text-sm text-gray-500">
                {searchDuration && (
                  <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium">
                    <Zap className="w-3 h-3" />
                    {formatDuration(searchDuration)}
                  </div>
                )}
                <span>{searchResults.length} results</span>
                {searchResponseQuery && (
                  <span className="text-gray-400">for "<span className="text-gray-600 font-medium">{searchResponseQuery}</span>"</span>
                )}
              </div>
              {searchNextPage && (
                <button className="text-xs text-primary hover:underline">
                  Next page
                </button>
              )}
            </div>

            {/* Results list - Google style */}
            <div className="space-y-6">
              {searchResults.map((result, idx) => {
                let hostname = '';
                try {
                  hostname = new URL(result.url).hostname.replace('www.', '');
                } catch {
                  hostname = result.displayed_url || result.url;
                }

                return (
                  <div key={idx} className="group">
                    {/* URL breadcrumb */}
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-7 h-7 rounded-full bg-gray-100 flex items-center justify-center overflow-hidden">
                        {hostname && (
                          <img
                            src={`https://www.google.com/s2/favicons?domain=${hostname}&sz=32`}
                            alt=""
                            className="w-4 h-4"
                            onError={(e) => {
                              (e.target as HTMLImageElement).style.display = 'none';
                            }}
                          />
                        )}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-sm text-gray-700">{hostname}</span>
                        {result.displayed_url && result.displayed_url !== hostname && (
                          <span className="text-xs text-gray-400 truncate max-w-md">{result.displayed_url}</span>
                        )}
                      </div>
                    </div>

                    {/* Title */}
                    <a
                      href={result.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xl font-medium text-blue-700 hover:underline block mb-1 group-hover:text-blue-800"
                    >
                      {decodeHtmlEntities(result.title)}
                    </a>

                    {/* Snippet */}
                    {result.snippet && (
                      <p className="text-gray-600 text-sm leading-relaxed line-clamp-2">
                        {result.snippet}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Crawl Status & Result */}
        {activeMenu === 'crawl' && (
          <>
             {crawlJobId && (
              <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 animate-fadeIn">
                 <div className="flex items-center justify-between mb-4">
                    <div className="flex flex-col">
                       <span className="text-sm text-gray-500">Job ID</span>
                       <span className="font-mono text-sm font-medium">{crawlJobId}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      {crawlDuration && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium">
                          <Zap className="w-3 h-3" />
                          {formatDuration(crawlDuration)}
                        </div>
                      )}
                      {crawlProgress && (
                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${crawlProgress.status === 'completed' ? 'bg-green-100 text-green-700' : crawlProgress.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-blue-100 text-blue-700'}`}>
                          {crawlProgress.status || 'Starting...'}
                        </span>
                      )}
                    </div>
                 </div>
                 
                 {crawlProgress && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs text-gray-500">
                         <span>Progress</span>
                         <span>{crawlProgress.pages_extracted || 0} / {crawlProgress.total_pages || crawlMaxPages} pages</span>
                      </div>
                      <div className="w-full bg-gray-100 rounded-full h-2 overflow-hidden">
                        <div
                          className="bg-primary h-2 rounded-full transition-all duration-500 ease-out"
                          style={{ width: `${crawlProgress.percentage || Math.min(((crawlProgress.pages_extracted || 0) / (crawlProgress.total_pages || crawlMaxPages || 1)) * 100, 100)}%` }}
                        ></div>
                      </div>
                      <div className="text-xs text-gray-400 truncate font-mono mt-2">
                        {crawlProgress.status === 'completed'
                          ? '✓ Completed'
                          : crawlProgress.status === 'failed'
                            ? '✗ Failed'
                            : crawlProgress.current_url || crawlProgress.message || 'Processing...'}
                      </div>
                    </div>
                 )}
              </div>
             )}

             {crawlResult && (
               <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden animate-fadeIn">
                 <div className="px-6 py-4 border-b border-gray-100 flex justify-between items-center bg-gray-50/50">
                    <div className="flex items-center gap-3">
                      <h3 className="font-semibold text-gray-700">Crawl Data</h3>
                      {crawlResult.duration_ms && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-50 text-emerald-700 rounded-full text-xs font-medium">
                          <Zap className="w-3 h-3" />
                          {formatDuration(crawlResult.duration_ms)}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-500">{crawlResult.successful_pages || crawlResult.total_pages || 0} Pages</span>
                      <span className="text-xs font-mono text-gray-500 uppercase">{crawlResult.output_format || crawlFormat}</span>
                      <button
                        onClick={() => copyResultToClipboard(crawlResult.content || '', 'crawl-content')}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                      >
                        {copiedResult === 'crawl-content' ? <Check className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedResult === 'crawl-content' ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                 </div>
                 <div className="p-6 overflow-x-auto max-h-[600px] overflow-y-auto">
                    {crawlResult.content ? (
                      (crawlResult.output_format || crawlFormat) === 'markdown' ? (
                        <article className="prose prose-emerald prose-sm max-w-none">
                          <ReactMarkdown>{crawlResult.content}</ReactMarkdown>
                        </article>
                      ) : (crawlResult.output_format || crawlFormat) === 'json' ? (
                        <pre className="text-xs font-mono text-gray-600 whitespace-pre-wrap bg-gray-50 p-4 rounded-lg">
                          {typeof crawlResult.content === 'object'
                            ? JSON.stringify(crawlResult.content, null, 2)
                            : crawlResult.content}
                        </pre>
                      ) : (
                        <pre className="text-sm font-mono text-gray-700 whitespace-pre-wrap leading-relaxed">
                          {crawlResult.content}
                        </pre>
                      )
                    ) : (
                      <pre className="text-xs font-mono text-gray-600 whitespace-pre-wrap bg-gray-50 p-4 rounded-lg">
                        {JSON.stringify(crawlResult, null, 2)}
                      </pre>
                    )}
                 </div>
               </div>
             )}
          </>
        )}
      </div>

      {/* Code Modal */}
      {showCodeModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 animate-fadeIn" onClick={() => setShowCodeModal(false)}>
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
              <h3 className="font-semibold text-gray-800 flex items-center gap-2">
                <Code className="w-5 h-5 text-primary" />
                Generated Code
              </h3>
              <button onClick={() => setShowCodeModal(false)} className="text-gray-400 hover:text-gray-600 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 bg-[#0d1117]">
               <pre className="text-sm font-mono text-gray-300 whitespace-pre-wrap break-all leading-relaxed">
                 {curlCode}
               </pre>
            </div>
            <div className="px-6 py-4 bg-gray-50 flex justify-end">
              <button 
                onClick={copyToClipboard}
                className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
              >
                {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                {copied ? 'Copied!' : 'Copy to clipboard'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
