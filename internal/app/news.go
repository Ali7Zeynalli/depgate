package app

import (
	"context"
	"sort"
	"time"

	"github.com/Ali7Zeynalli/depgate/internal/i18n"
	"github.com/Ali7Zeynalli/depgate/internal/news"
	"github.com/Ali7Zeynalli/depgate/internal/report"
	"github.com/Ali7Zeynalli/depgate/internal/sources"
)

// newsEvery is how often the news are fetched again (the feeds are cached a
// little less, so each round reads them fresh).
const newsEvery = time.Hour

// NewsAlert is the newest unread item that is about the user's stack and is
// exploited in real attacks: the red strip shows it.
type NewsAlert struct {
	ID    string `json:"id"`
	Title i18n.T `json:"title"`
	Where string `json:"where"`
}

// NewsView is what the news page shows.
type NewsView struct {
	news.Feed
	Read     map[string]bool      `json:"read"`
	Busy     bool                 `json:"busy"`
	Settings news.Settings        `json:"settings"`
	Catalog  []sources.NewsSource `json:"catalog"` // every general source, on or off
	Topics   []string             `json:"topics"`
}

func (m *Manager) newsStore() *news.Store {
	m.newsOnce.Do(func() { m.newsSt = &news.Store{Dir: m.Store.Dir} })
	return m.newsSt
}

// newsLoop builds the news shortly after start, every hour, and after scans.
func (m *Manager) newsLoop(ctx context.Context) {
	first := time.NewTimer(30 * time.Second)
	tick := time.NewTicker(newsEvery)
	defer first.Stop()
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		case <-m.newsKick:
			// let a burst of scans finish first
			select {
			case <-ctx.Done():
				return
			case <-time.After(20 * time.Second):
			}
		}
		_ = m.RefreshNews(ctx)
	}
}

// kickNews asks for a rebuild (after scans: the stack may have changed).
func (m *Manager) kickNews() {
	select {
	case m.newsKick <- struct{}{}:
	default:
	}
}

// RefreshNews builds the news now.
func (m *Manager) RefreshNews(ctx context.Context) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	m.mu.Lock()
	if m.newsBusy {
		m.mu.Unlock()
		return nil
	}
	m.newsBusy = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.newsBusy = false; m.mu.Unlock() }()
	var ps []*report.Project
	for _, e := range m.Store.Projects() {
		if p := m.Store.Report(e.Dir); p != nil {
			ps = append(ps, p)
		}
	}
	st := m.newsStore()
	feed := news.Build(ctx, m.Fetcher(), ps, news.Options{Now: time.Now(), FirstSee: st.FirstSeen(), Settings: st.Settings()})
	return st.Save(feed)
}

// News returns the feed and what was read.
func (m *Manager) News() (*NewsView, error) {
	if m.ro != nil {
		return &NewsView{Feed: news.Feed{Items: []news.Item{}}, Read: map[string]bool{}, Settings: news.Settings{}.Clean(), Catalog: sources.NewsSources, Topics: sources.NewsTopics}, nil
	}
	m.mu.Lock()
	busy := m.newsBusy
	m.mu.Unlock()
	st := m.newsStore()
	set := st.Settings()
	return &NewsView{Feed: st.Feed(), Read: st.Read(), Busy: busy, Settings: set, Catalog: news.All(set), Topics: sources.NewsTopics}, nil
}

// SetNewsSettings stores which general sources are read and rebuilds the news.
func (m *Manager) SetNewsSettings(set news.Settings) (news.Settings, error) {
	if m.ro != nil {
		return set, ErrReadOnly
	}
	out, err := m.newsStore().SaveSettings(set)
	if err == nil {
		m.kickNews()
	}
	return out, err
}

// MarkNews marks items read (or unread again); all marks every item of the feed.
func (m *Manager) MarkNews(ids []string, all, unread bool) error {
	if m.ro != nil {
		return ErrReadOnly
	}
	st := m.newsStore()
	if all {
		ids = ids[:0]
		for _, it := range st.Feed().Items {
			ids = append(append(ids, it.ID), it.Alias...)
		}
	}
	return st.MarkRead(ids, unread)
}

// newsSummary fills the state's news counters.
func (m *Manager) newsSummary(s *State) {
	st := m.newsStore()
	f, read := st.Feed(), st.Read()
	if !f.Updated.IsZero() {
		t := f.Updated
		s.NewsAt = &t
	}
	var alert []news.Item
	for _, it := range f.Items {
		if news.IsRead(it, read) || !news.Notable(it) {
			continue
		}
		s.NewsUnread++
		if it.Mine {
			s.NewsMine++
			if it.KEV {
				alert = append(alert, it)
			}
		}
	}
	if len(alert) > 0 {
		sort.Slice(alert, func(i, j int) bool { return alert[i].At.After(alert[j].At) })
		a := alert[0]
		w := ""
		if len(a.Where) > 0 {
			w = a.Where[0].Project + " · " + a.Where[0].File
			if a.Where[0].Image != "" {
				w += " → " + a.Where[0].Image
			}
		}
		s.NewsAlert = &NewsAlert{ID: a.ID, Title: a.Title, Where: w}
	}
}
