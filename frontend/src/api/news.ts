import apiClient from './client'

export type NewsCategory =
  | 'general'
  | 'threat-intel'
  | 'gov-alerts'
  | 'darkweb'
  | 'high-quality'
  | 'world-news'
  | 'vn-target'
  // Not an RSS feed: produced by the plugin-release-watch service and folded in
  // by the backend's plugin-watch worker.
  | 'wp-plugin-watch'

// PluginRelease is attached only to wp-plugin-watch articles: the facts an
// analyst triages on, as data rather than prose inside the headline.
export interface PluginRelease {
  slug: string
  name: string
  version: string
  previous_version?: string
  /** wordpress.org rounds this DOWN into buckets — a floor, not a count. */
  active_installs: number
  /** The same figure rendered with its "+", so the caveat is never lost. */
  active_installs_label: string
  /** Cumulative downloads. Unlike active_installs this IS exact. Absent for a
   *  plugin with none yet, so the UI must not assume it is present. */
  downloads?: number
  signal: 'security_fix' | 'new_plugin' | 'release'
  last_updated?: string
}

export interface NewsArticle {
  id: string
  title: string
  link: string
  description: string
  author?: string
  published: string
  source: string
  category: NewsCategory
  language?: string
  tags?: string[]
  fetched_at: string
  image_url?: string
  /** Present only for wp-plugin-watch articles. */
  plugin?: PluginRelease
}

export interface NewsCategoryMeta {
  slug: NewsCategory
  label: string
  icon: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const newsApi = {
  list: async (category?: NewsCategory): Promise<NewsArticle[]> => {
    if (category === 'vn-target') {
      const { data } = await apiClient.get<ApiResponse<NewsArticle[]>>('/news')
      return data.data.filter((a) => {
        if (a.category === 'world-news') return false
        const text = `${a.title} ${a.description} ${a.tags?.join(' ') || ''}`
        return /(vietnam|việt nam)/i.test(text)
      })
    }
    const path = category ? `/news?category=${encodeURIComponent(category)}` : '/news'
    const { data } = await apiClient.get<ApiResponse<NewsArticle[]>>(path)
    return data.data
  },

  categories: async (): Promise<NewsCategoryMeta[]> => {
    const { data } = await apiClient.get<ApiResponse<NewsCategoryMeta[]>>('/news/categories')
    return data.data
  },
}
