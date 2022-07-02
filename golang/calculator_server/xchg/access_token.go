package xchg

type AccessToken struct {
	token      string
	properties map[string]string
}

func NewAccessToken() *AccessToken {
	var c AccessToken
	c.properties = make(map[string]string)
	return &c
}

func (c *AccessToken) Set(key string, value string) {
	c.properties[key] = value
}

func (c *AccessToken) Get(key string) (value string) {
	if valueFromMap, ok := c.properties[key]; ok {
		value = valueFromMap
		return
	}
	return
}
