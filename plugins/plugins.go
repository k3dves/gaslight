package plugins

import (
	"context"

	"go.uber.org/zap"
)

func SimpleLogger(ctx context.Context, data *[]byte) error {
	log := ctx.Value("logger").(*zap.SugaredLogger)
	name := "simple_logger"
	log.Info("Running plugin ", "name ", name)
	log.Info("data : ", string(*data))
	return nil
}
