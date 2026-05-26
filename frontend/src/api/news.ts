import apiClient from './client'

export type NewsCategory =
  | 'general'
  | 'threat-intel'
  | 'gov-alerts'
  | 'darkweb'
  | 'high-quality'
  | 'world-news'
  | 'vn-target'

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
